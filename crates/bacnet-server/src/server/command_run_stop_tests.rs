//! A Command run the server lets go of ends rather than leaving the Command
//! in process (#1252): one `stop()` cancels in a post delay, one let go of
//! while the database is busy, one no task ever started, one nothing took,
//! and one whose write panics. A Channel's distribution, the other run kind,
//! ends FAILED in the same cases.
//!
//! CMD-1 has two lists: AO-1 to 50.0 at priority 8, and AO-2 to 30.0 at
//! priority 8 with a 5-second post delay, then AO-1 to 70.0. Every command
//! starts with its write-successful flag TRUE, so a FALSE is the run's doing.
//! After `stop()` everything is read from the database. The clock is paused.
use super::channel_wire_tests::{ch, channel, encoded, member};
use super::command_action_wire_tests::{
    ao, cmd, outputs, read_db, slot8, write, write_property, write_pv,
};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_encoding::constructed::decode_action_list;
use bacnet_objects::command::CommandObject;
use bacnet_objects::traits::BACnetObject;
use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};
use bacnet_types::enums::WriteStatus;
use std::borrow::Cow;

fn objects(db: &mut ObjectDatabase) {
    outputs(db);
    let delayed = BACnetActionCommand {
        post_delay: Some(5),
        ..write(ao(2), PropertyValue::Real(30.0), 8)
    };
    let mut command = CommandObject::new(1, "CMD-1").unwrap();
    command
        .set_action(vec![
            BACnetActionList {
                commands: vec![write(ao(1), PropertyValue::Real(50.0), 8)],
            },
            BACnetActionList {
                commands: vec![delayed, write(ao(1), PropertyValue::Real(70.0), 8)],
            },
        ])
        .unwrap();
    db.add(Box::new(command)).unwrap();
}

/// CMD-`instance`'s In_Process and All_Writes_Successful, from the database.
pub(super) async fn db_state(h: &Harness, instance: u32) -> (bool, bool) {
    let flag = |value| match value {
        PropertyValue::Boolean(flag) => flag,
        other => panic!("not a BOOLEAN: {other:?}"),
    };
    (
        flag(read_db(h, cmd(instance), PropertyIdentifier::IN_PROCESS, None).await),
        flag(
            read_db(
                h,
                cmd(instance),
                PropertyIdentifier::ALL_WRITES_SUCCESSFUL,
                None,
            )
            .await,
        ),
    )
}

/// The write-successful flags of CMD-1's Action element `index`, from the
/// database.
pub(super) async fn db_flags(h: &Harness, index: u32) -> Vec<bool> {
    let PropertyValue::ApplicationData(element) =
        read_db(h, cmd(1), PropertyIdentifier::ACTION, Some(index)).await
    else {
        panic!("an encoded action list");
    };
    let (list, _) = decode_action_list(&element, 0).unwrap();
    list.commands
        .iter()
        .map(|command| command.write_successful)
        .collect()
}

#[tokio::test(start_paused = true)]
async fn stop_during_a_post_delay_ends_the_run_with_what_it_made() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    write_pv(&mut h, 1, 2).await.unwrap();
    h.settle().await;
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(30.0));
    assert_eq!(db_state(&h, 1).await, (true, false));

    h.server.stop().await.unwrap();
    assert_eq!(db_state(&h, 1).await, (false, false));
    // The first write was made; the one the delay held back never was.
    assert_eq!(db_flags(&h, 2).await, [true, false]);
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn stop_while_the_database_is_busy_ends_the_run_where_it_stood() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    write_pv(&mut h, 1, 2).await.unwrap();
    h.settle().await;
    // An application holds the database through `stop()`, so the run can't
    // be ended as it's let go of, and `stop()` doesn't wait for the database:
    // the run ends, keeping what it made, once the application lets go.
    let held = Arc::clone(h.server.database()).read_owned().await;
    h.server.stop().await.unwrap();
    drop(held);
    h.settle().await;
    assert_eq!(db_state(&h, 1).await, (false, false));
    assert_eq!(db_flags(&h, 2).await, [true, false]);
}

#[tokio::test(start_paused = true)]
async fn run_no_task_starts_ends_at_once_as_unsuccessful() {
    let h = Harness::start_with(ServerConfig::default(), objects).await;
    // A closed task set refuses the run's task, as it does once `stop()`
    // has begun.
    h.server.request_tasks.close();
    h.server
        .write_local(
            &cmd(1),
            PV,
            None,
            PropertyValue::Unsigned(2),
            None,
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    assert_eq!(db_state(&h, 1).await, (false, false));
    assert_eq!(db_flags(&h, 2).await, [false, false]);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}

/// The objects plus CH-5, which writes AO-2 200 ms after its Present_Value
/// is written.
fn with_channel(db: &mut ObjectDatabase) {
    objects(db);
    db.add(Box::new(channel(5, 5, vec![(member(ao(2), PV), 200)])))
        .unwrap();
}

/// CH-5's Write_Status, from the database.
async fn channel_status(h: &Harness) -> WriteStatus {
    match read_db(h, ch(5), PropertyIdentifier::WRITE_STATUS, None).await {
        PropertyValue::Enumerated(raw) => WriteStatus::from_raw(raw),
        other => panic!("not an ENUMERATED: {other:?}"),
    }
}

/// Start CH-5's distribution over the wire; it waits out the member's delay.
async fn start_distribution(h: &mut Harness) {
    write_property(h, ch(5), encoded(&PropertyValue::Real(12.0)), Some(8))
        .await
        .unwrap();
    assert_eq!(channel_status(h).await, WriteStatus::IN_PROGRESS);
}

#[tokio::test(start_paused = true)]
async fn stop_during_a_channel_member_delay_ends_the_distribution_failed() {
    let mut h = Harness::start_with(ServerConfig::default(), with_channel).await;
    start_distribution(&mut h).await;
    h.server.stop().await.unwrap();
    assert_eq!(channel_status(&h).await, WriteStatus::FAILED);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn stop_while_the_database_is_busy_ends_a_channel_distribution_failed() {
    let mut h = Harness::start_with(ServerConfig::default(), with_channel).await;
    start_distribution(&mut h).await;
    let held = Arc::clone(h.server.database()).read_owned().await;
    h.server.stop().await.unwrap();
    drop(held);
    h.settle().await;
    assert_eq!(channel_status(&h).await, WriteStatus::FAILED);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn channel_run_no_task_starts_ends_at_once_failed() {
    let h = Harness::start_with(ServerConfig::default(), with_channel).await;
    h.server.request_tasks.close();
    h.server
        .write_local(
            &ch(5),
            PV,
            None,
            PropertyValue::Real(12.0),
            Some(8),
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    assert_eq!(channel_status(&h).await, WriteStatus::FAILED);
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn stop_ends_a_run_nothing_took() {
    let mut h = Harness::start_with(ServerConfig::default(), with_channel).await;
    // Written straight into the database, each run stays queued on its object
    // with nothing to take it.
    {
        let mut db = h.server.database().write().await;
        db.get_mut(&cmd(1))
            .unwrap()
            .write_property(PV, None, PropertyValue::Unsigned(2), None)
            .unwrap();
        db.get_mut(&ch(5))
            .unwrap()
            .write_property(PV, None, PropertyValue::Real(12.0), Some(8))
            .unwrap();
    }
    assert_eq!(db_state(&h, 1).await, (true, false));
    assert_eq!(channel_status(&h).await, WriteStatus::IN_PROGRESS);

    h.server.stop().await.unwrap();
    assert_eq!(db_state(&h, 1).await, (false, false));
    assert_eq!(db_flags(&h, 2).await, [false, false]);
    assert_eq!(channel_status(&h).await, WriteStatus::FAILED);
}

fn boom() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::from_raw(600), 7).unwrap()
}

/// A vendor-type object whose every write panics.
struct Panicking;

impl BACnetObject for Panicking {
    fn object_identifier(&self) -> ObjectIdentifier {
        boom()
    }

    fn object_name(&self) -> &str {
        "BOOM-7"
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        Ok(match property {
            PropertyIdentifier::OBJECT_IDENTIFIER => PropertyValue::ObjectIdentifier(boom()),
            PropertyIdentifier::OBJECT_NAME => PropertyValue::CharacterString("BOOM-7".into()),
            PropertyIdentifier::OBJECT_TYPE => PropertyValue::Enumerated(600),
            _ => PropertyValue::Real(0.0),
        })
    }

    fn write_property(
        &mut self,
        _property: PropertyIdentifier,
        _array_index: Option<u32>,
        _value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        panic!("BOOM-7 refuses every write by panicking");
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        Cow::Borrowed(&[])
    }
}

#[tokio::test(start_paused = true)]
async fn run_whose_write_panics_ends_with_its_unmade_commands_unsuccessful() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        objects(db);
        db.add(Box::new(Panicking)).unwrap();
        let mut command = CommandObject::new(2, "CMD-2").unwrap();
        command
            .set_action(vec![BACnetActionList {
                commands: vec![
                    write(boom(), PropertyValue::Real(1.0), 8),
                    write(ao(1), PropertyValue::Real(50.0), 8),
                ],
            }])
            .unwrap();
        db.add(Box::new(command)).unwrap();
    })
    .await;
    let mut body = BytesMut::new();
    bacnet_services::cov::SubscribeCOVPropertyRequest {
        subscriber_process_identifier: 7,
        monitored_object_identifier: cmd(2),
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
    response(&h).await.unwrap();
    let in_process = |notification: bacnet_services::cov::COVNotificationRequest| {
        notification.list_of_values[0].value.clone()
    };
    assert_eq!(in_process(h.cov_notification().await), [0x10]);

    write_pv(&mut h, 2, 1).await.unwrap();
    assert_eq!(in_process(h.cov_notification().await), [0x11]);
    // The panic ends the run, and its subscriber hears In_Process fall.
    assert_eq!(in_process(h.cov_notification().await), [0x10]);
    assert_eq!(db_state(&h, 2).await, (false, false));
    let PropertyValue::ApplicationData(element) =
        read_db(&h, cmd(2), PropertyIdentifier::ACTION, Some(1)).await
    else {
        panic!("an encoded action list");
    };
    let (list, _) = decode_action_list(&element, 0).unwrap();
    let flags: Vec<_> = list.commands.iter().map(|c| c.write_successful).collect();
    assert_eq!(flags, [false, false]);
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Null);
}
