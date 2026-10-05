//! A `write_local` dropped once its write has committed still does all the
//! write owes (#1367). The commit hands its database guard, and what the
//! write owes, to a task of its own in the request task set, which the
//! caller only waits for: a caller that drops the future (a timeout, a
//! `select!`, a cancelled Python task) skips none of it. Subscribers hear of
//! the change, and a Command or Channel run the write started goes ahead
//! and reports its end. `stop()` aborts that task with the other request
//! tasks, so a run it hadn't started ends as if none of its writes were made
//! (#1324).
//!
//! Each test holds the COV table for writing, so the work after the commit
//! parks on it, at the timestamped capture under the write's guard; polls the
//! write once by hand, which commits it; and drops it there. The objects are
//! those of `command_run_stop_tests`: CMD-1's list 2 writes AO-2 with a
//! 5-second post delay, then AO-1, and CH-5 writes AO-2 200 ms after its
//! Present_Value is written. The clock is paused.
use super::channel_wire_tests::ch;
use super::command_action_wire_tests::{ao, cmd, idle, read_db, slot8};
use super::command_run_stop_tests::{channel_status, db_flags, db_state, objects, with_channel};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_types::enums::WriteStatus;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Waker};

type Write<'a> = Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>>;

/// `write_local` of `value` to `object`'s Present_Value, from the Device.
fn write_local<'a>(
    h: &'a Harness,
    object: &'a ObjectIdentifier,
    value: PropertyValue,
    priority: Option<u8>,
) -> Write<'a> {
    Box::pin(h.server.write_local(
        object,
        PV,
        None,
        value,
        priority,
        crate::LocalCommandSource::ServerDevice,
    ))
}

/// Commit `write`, polled once, and drop it at its first wait, the work it
/// owes parked on the COV table `h`'s caller holds.
fn commit_and_drop(h: &Harness, mut write: Write<'_>) {
    assert!(write
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    // Committed: the database is held for the work after the commit.
    assert!(h.server.database().try_read().is_err());
    drop(write);
}

/// SubscribeCOVProperty from process 7 to CMD-1's In_Process, and its first
/// notification's value.
async fn subscribe_in_process(h: &mut Harness) -> Vec<u8> {
    let mut body = BytesMut::new();
    bacnet_services::cov::SubscribeCOVPropertyRequest {
        subscriber_process_identifier: 7,
        monitored_object_identifier: cmd(1),
        issue_confirmed_notifications: Some(false),
        lifetime: Some(300),
        monitored_property_identifier: PropertyIdentifier::IN_PROCESS,
        monitored_property_array_index: None,
        cov_increment: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY, body)
        .await;
    response(h).await.unwrap();
    in_process(h).await
}

/// The value of the next In_Process notification: `[0x11]` for TRUE,
/// `[0x10]` for FALSE.
async fn in_process(h: &Harness) -> Vec<u8> {
    let notification = h.cov_notification().await;
    assert_eq!(notification.monitored_object_identifier, cmd(1));
    notification.list_of_values[0].value.clone()
}

#[tokio::test(start_paused = true)]
async fn write_local_dropped_after_its_commit_still_notifies_cov_subscribers() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe_cov().await;
    h.cov_notification().await;
    let table = Arc::clone(&h.server.cov_table).write_owned().await;
    let target = av1();
    commit_and_drop(
        &h,
        write_local(&h, &target, PropertyValue::Real(70.0), None),
    );

    drop(table);
    let notification = h.cov_notification().await;
    assert_eq!(notification.monitored_object_identifier, av1());
    assert_eq!(notification.list_of_values[0].property_identifier, PV);
    assert_eq!(notification.list_of_values[0].value, real(70.0));
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn write_local_dropped_after_its_commit_still_runs_the_command_and_reports_its_end() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    assert_eq!(subscribe_in_process(&mut h).await, [0x10]);
    let table = Arc::clone(&h.server.cov_table).write_owned().await;
    let target = cmd(1);
    commit_and_drop(
        &h,
        write_local(&h, &target, PropertyValue::Unsigned(2), None),
    );

    drop(table);
    idle(&h, 1).await;
    // The subscriber hears the run start and, after its post delay, end,
    // with every write made.
    assert_eq!(in_process(&h).await, [0x11]);
    assert_eq!(in_process(&h).await, [0x10]);
    assert_eq!(db_state(&h, 1).await, (false, true));
    assert_eq!(db_flags(&h, 2).await, [true, true]);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(30.0));
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(70.0));
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn write_local_dropped_after_its_commit_still_runs_the_distribution() {
    let h = Harness::start_with(ServerConfig::default(), with_channel).await;
    let table = Arc::clone(&h.server.cov_table).write_owned().await;
    let target = ch(5);
    commit_and_drop(
        &h,
        write_local(&h, &target, PropertyValue::Real(12.0), Some(8)),
    );

    drop(table);
    assert_eq!(channel_status(&h).await, WriteStatus::IN_PROGRESS);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(channel_status(&h).await, WriteStatus::SUCCESSFUL);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(12.0));
}

#[tokio::test(start_paused = true)]
async fn stop_aborts_the_work_a_committed_write_owes_and_ends_its_run() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    let table = Arc::clone(&h.server.cov_table).write_owned().await;
    let target = cmd(1);
    commit_and_drop(
        &h,
        write_local(&h, &target, PropertyValue::Unsigned(2), None),
    );
    drop(table);
    assert!(
        !h.server.request_tasks.is_empty(),
        "the work the write owes is a request task"
    );

    // `stop()` closes the request task set before anything else, so the
    // task never runs: it is aborted as a request handler would be, and the
    // run it held ends unsuccessful with none of its writes made.
    h.server.stop().await.unwrap();
    assert_eq!(db_state(&h, 1).await, (false, false));
    assert_eq!(db_flags(&h, 2).await, [false, false]);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
    assert_eq!(
        read_db(&h, cmd(1), PropertyIdentifier::PRESENT_VALUE, None).await,
        PropertyValue::Unsigned(2)
    );
}
