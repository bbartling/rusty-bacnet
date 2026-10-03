//! The other routes into a Command object's run, and what it reports, on a
//! running server (#1150, Clause 12.10).
//!
//! CMD-1 has two lists: AO-1 to 50.0 at priority 8, and AO-1 to 70.0 at
//! priority 8 after a 5-second wait on AO-2. CMD-2's one list writes 1 to
//! CMD-1's Present_Value. The clock is paused.
use super::command_action_wire_tests::{
    ao, cmd, idle, outputs, read_db, slot8, state, write, write_property, write_pv,
};
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::command::CommandObject;
use bacnet_objects::schedule::ScheduleObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_types::constructed::{
    BACnetActionCommand, BACnetActionList, BACnetObjectPropertyReference,
};
use bacnet_types::enums::ObjectType;

fn cmd1() -> CommandObject {
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
    command
}

fn objects(db: &mut ObjectDatabase) {
    outputs(db);
    db.add(Box::new(cmd1())).unwrap();
    let mut cmd2 = CommandObject::new(2, "CMD-2").unwrap();
    cmd2.set_action(vec![BACnetActionList {
        commands: vec![BACnetActionCommand {
            priority: None,
            ..write(cmd(1), PropertyValue::Unsigned(1), 16)
        }],
    }])
    .unwrap();
    db.add(Box::new(cmd2)).unwrap();
}

fn unsigned(value: u64) -> Vec<u8> {
    let mut encoded = BytesMut::new();
    encode_property_value(&mut encoded, &PropertyValue::Unsigned(value)).unwrap();
    encoded.to_vec()
}

/// One WritePropertyMultiple of CMD-1's Present_Value, once per value.
async fn write_pv_multiple(h: &mut Harness, values: &[u64]) -> Result<(), ErrorCode> {
    let mut body = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: cmd(1),
            list_of_properties: values
                .iter()
                .map(|value| BACnetPropertyValue {
                    property_identifier: PV,
                    property_array_index: None,
                    value: unsigned(*value),
                    priority: None,
                })
                .collect(),
        }],
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE, body)
        .await;
    response(h).await
}

/// Release AO-1's slot 8, so the next run's write there shows.
async fn relinquish_ao1(h: &mut Harness) {
    write_property(h, ao(1), vec![0x00], Some(8)).await.unwrap();
    assert_eq!(slot8(h, ao(1)).await, PropertyValue::Null);
}

#[tokio::test(start_paused = true)]
async fn command_run_starts_from_write_local_and_write_property_multiple() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    h.server
        .write_local(
            &cmd(1),
            PV,
            None,
            PropertyValue::Unsigned(1),
            None,
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    idle(&h, 1).await;
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(50.0));

    relinquish_ao1(&mut h).await;
    write_pv_multiple(&mut h, &[1]).await.unwrap();
    idle(&h, 1).await;
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(50.0));

    // Twice in one request: the first write starts list 2, so the second
    // finds CMD-1 busy, and the run the first started still finishes.
    relinquish_ao1(&mut h).await;
    assert_eq!(
        write_pv_multiple(&mut h, &[2, 1]).await,
        Err(ErrorCode::BUSY)
    );
    assert_eq!(
        read_db(&h, cmd(1), PV, None).await,
        PropertyValue::Unsigned(2)
    );
    idle(&h, 1).await;
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(70.0));
    assert_eq!(state(&mut h, 1).await, (false, true));
}

#[tokio::test(start_paused = true)]
async fn command_run_writing_another_command_starts_its_list() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    write_pv(&mut h, 2, 1).await.unwrap();
    idle(&h, 2).await;
    idle(&h, 1).await;
    assert_eq!(
        read_db(&h, cmd(1), PV, None).await,
        PropertyValue::Unsigned(1)
    );
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(50.0));
    assert_eq!(state(&mut h, 2).await, (false, true));
    assert_eq!(state(&mut h, 1).await, (false, true));
}

#[tokio::test(start_paused = true)]
async fn command_property_subscribers_see_in_process_rise_and_fall() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    let mut body = BytesMut::new();
    bacnet_services::cov::SubscribeCOVPropertyRequest {
        subscriber_process_identifier: 891,
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
    response(&h).await.unwrap();
    let in_process = |notification: bacnet_services::cov::COVNotificationRequest| {
        assert_eq!(notification.monitored_object_identifier, cmd(1));
        let value = &notification.list_of_values[0];
        assert_eq!(value.property_identifier, PropertyIdentifier::IN_PROCESS);
        // Command has Status_Flags, so Table 13-1a adds them to the report.
        assert_eq!(notification.list_of_values[1].property_identifier, SF);
        value.value.clone()
    };
    assert_eq!(in_process(h.cov_notification().await), [0x10]);

    write_pv(&mut h, 1, 2).await.unwrap();
    assert_eq!(in_process(h.cov_notification().await), [0x11]);
    idle(&h, 1).await;
    assert_eq!(in_process(h.cov_notification().await), [0x10]);
}

#[tokio::test(start_paused = true)]
async fn command_replaced_during_a_post_delay_leaves_the_rest_of_the_run_unmade() {
    let mut h = Harness::start_with(ServerConfig::default(), objects).await;
    write_pv(&mut h, 1, 2).await.unwrap();
    h.settle().await;
    assert_eq!(slot8(&h, ao(2)).await, PropertyValue::Real(30.0));
    // The application puts a fresh CMD-1 in place while the run waits.
    h.server
        .database()
        .write()
        .await
        .add(Box::new(cmd1()))
        .unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Null);
    assert_eq!(state(&mut h, 1).await, (false, true));
    write_pv(&mut h, 1, 1).await.unwrap();
    idle(&h, 1).await;
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(50.0));
}

fn sch5() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::SCHEDULE, 5).unwrap()
}

#[tokio::test(start_paused = true)]
async fn command_run_starts_when_a_schedule_writes_present_value() {
    // SCH-5 drives CMD-1's Present_Value and defaults to 1; the start-up
    // tick writes that default.
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        objects(db);
        let mut schedule = ScheduleObject::new(5, "SCH-5", PropertyValue::Unsigned(1)).unwrap();
        schedule
            .add_object_property_reference(BACnetObjectPropertyReference::new(cmd(1), PV.to_raw()))
            .unwrap();
        db.add(Box::new(schedule)).unwrap();
    })
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while slot8(&h, ao(1)).await != PropertyValue::Real(50.0) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the start-up tick ran list 1");
    idle(&h, 1).await;
    assert_eq!(state(&mut h, 1).await, (false, true));

    // A new default takes effect at once, through the written Schedule's
    // own pass.
    let mut body = BytesMut::new();
    bacnet_services::write_property::WritePropertyRequest {
        object_identifier: sch5(),
        property_identifier: PropertyIdentifier::SCHEDULE_DEFAULT,
        property_array_index: None,
        property_value: unsigned(2),
        priority: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
        .await;
    response(&h).await.unwrap();
    assert_eq!(
        read_db(&h, cmd(1), PV, None).await,
        PropertyValue::Unsigned(2)
    );
    idle(&h, 1).await;
    assert_eq!(slot8(&h, ao(1)).await, PropertyValue::Real(70.0));
    assert_eq!(state(&mut h, 1).await, (false, true));
}
