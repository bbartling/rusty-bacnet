//! Command and Channel runs that write back into themselves stop after one
//! round (#1151 review).
//!
//! Every loop here spaces its writes so the first object is idle again before
//! the write comes back, which is the case its own busy refusal can't catch.
//! The clock is paused, so delays pass only when a test sleeps through them.
use super::channel_wire_tests::{ch, channel, member, settled, slot, write_channel, write_status};
use super::command_action_wire_tests::{ao, cmd, outputs, read_db, state, write};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::command::CommandObject;
use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};
use bacnet_types::enums::WriteStatus;

/// A Command whose one list is `commands`.
fn command(instance: u32, commands: Vec<BACnetActionCommand>) -> CommandObject {
    let mut command = CommandObject::new(instance, format!("CMD-{instance}")).unwrap();
    command
        .set_action(vec![BACnetActionList { commands }])
        .unwrap();
    command
}

/// A write of `value` to `object`'s Present_Value with no priority.
fn plain(object: ObjectIdentifier, value: PropertyValue) -> BACnetActionCommand {
    BACnetActionCommand {
        priority: None,
        ..write(object, value, 16)
    }
}

/// A command that writes AO-1 and then waits a second, so whatever follows
/// it comes back after the object that started the run has gone idle.
fn pause() -> BACnetActionCommand {
    BACnetActionCommand {
        post_delay: Some(1),
        ..write(ao(1), PropertyValue::Real(5.0), 8)
    }
}

/// Whether any of `channels` is IN_PROGRESS or any of `commands` In_Process.
async fn busy(h: &Harness, channels: &[u32], commands: &[u32]) -> bool {
    for &instance in channels {
        if read_db(h, ch(instance), PropertyIdentifier::WRITE_STATUS, None).await
            == PropertyValue::Enumerated(WriteStatus::IN_PROGRESS.to_raw())
        {
            return true;
        }
    }
    for &instance in commands {
        if read_db(h, cmd(instance), PropertyIdentifier::IN_PROCESS, None).await
            == PropertyValue::Boolean(true)
        {
            return true;
        }
    }
    false
}

/// Check, every 10 ms for `seconds`, that none of the objects starts again.
async fn assert_quiet(h: &Harness, seconds: u64, channels: &[u32], commands: &[u32]) {
    for _ in 0..seconds * 100 {
        assert!(!busy(h, channels, commands).await, "a run started again");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn run_cycle_two_channels_naming_each_other_stop_after_one_round_trip() {
    // CH-5 writes CH-6 after 100 ms and CH-6 writes CH-5 after 100 ms.
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(channel(5, 1, vec![(member(ch(6), PV), 100)])))
            .unwrap();
        db.add(Box::new(channel(6, 2, vec![(member(ch(5), PV), 100)])))
            .unwrap();
    })
    .await;
    write_channel(&mut h, 5, &PropertyValue::Real(1.0), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    // CH-6 wrote CH-5 back after CH-5 had finished; CH-5's second run would
    // have started its own object again, so it ended FAILED and CH-6's write
    // failed with it.
    assert_eq!(settled(&mut h, 5).await, WriteStatus::FAILED);
    assert_eq!(settled(&mut h, 6).await, WriteStatus::FAILED);
    assert_quiet(&h, 2, &[5, 6], &[]).await;
    assert_eq!(read_db(&h, ch(6), PV, None).await, PropertyValue::Real(1.0));
}

#[tokio::test(start_paused = true)]
async fn run_cycle_a_channel_and_a_command_naming_each_other_stop() {
    // CH-7 writes CMD-4 after 100 ms; CMD-4's list pauses a second, then
    // writes CH-7 back.
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        outputs(db);
        db.add(Box::new(channel(7, 3, vec![(member(cmd(4), PV), 100)])))
            .unwrap();
        db.add(Box::new(command(
            4,
            vec![pause(), plain(ch(7), PropertyValue::Unsigned(1))],
        )))
        .unwrap();
    })
    .await;
    write_channel(&mut h, 7, &PropertyValue::Unsigned(1), None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(settled(&mut h, 7).await, WriteStatus::FAILED);
    // CMD-4's write to CH-7 is the one that failed.
    assert_eq!(state(&mut h, 4).await, (false, false));
    assert_quiet(&h, 3, &[7], &[4]).await;
}

#[tokio::test(start_paused = true)]
async fn run_cycle_two_commands_naming_each_other_stop() {
    // Each pauses a second, then writes the other.
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        outputs(db);
        db.add(Box::new(command(
            5,
            vec![pause(), plain(cmd(6), PropertyValue::Unsigned(1))],
        )))
        .unwrap();
        db.add(Box::new(command(
            6,
            vec![pause(), plain(cmd(5), PropertyValue::Unsigned(1))],
        )))
        .unwrap();
    })
    .await;
    h.server
        .write_local(
            &cmd(5),
            PV,
            None,
            PropertyValue::Unsigned(1),
            None,
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    h.settle().await;
    // CMD-5's second run was ended as failed, and CMD-6's write with it.
    assert_eq!(state(&mut h, 5).await, (false, false));
    assert_eq!(state(&mut h, 6).await, (false, false));
    assert_quiet(&h, 3, &[], &[5, 6]).await;
}

#[tokio::test(start_paused = true)]
async fn run_cycle_a_chain_of_ten_channels_stops_past_eight_runs_deep() {
    // CH-11 writes CH-12, which writes CH-13, and so on; CH-20 writes AO-1.
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        outputs(db);
        for instance in 11..20 {
            db.add(Box::new(channel(
                instance,
                1,
                vec![(member(ch(instance + 1), PV), 0)],
            )))
            .unwrap();
        }
        db.add(Box::new(channel(20, 1, vec![(member(ao(1), PV), 0)])))
            .unwrap();
    })
    .await;
    write_channel(&mut h, 11, &PropertyValue::Real(7.0), Some(8))
        .await
        .unwrap();
    for instance in 11..19 {
        assert_eq!(
            settled(&mut h, instance).await,
            WriteStatus::SUCCESSFUL,
            "CH-{instance}"
        );
    }
    // CH-20's run would have had nine runs above it: it ended FAILED without
    // writing AO-1, and CH-19's write to it failed.
    assert_eq!(settled(&mut h, 19).await, WriteStatus::FAILED);
    assert_eq!(write_status(&mut h, 20).await, WriteStatus::FAILED);
    assert_eq!(
        read_db(&h, ch(20), PV, None).await,
        PropertyValue::Real(7.0)
    );
    assert_eq!(slot(&h, ao(1), 8).await, PropertyValue::Null);
}
