//! Schedule writes on a running server (#1057): WriteProperty,
//! WritePropertyMultiple and `write_local` of Weekly_Schedule,
//! Exception_Schedule and Effective_Period, each followed at once by the
//! schedule pass for that Schedule and COV for the target it commands.
//!
//! The harness clock reads Tuesday 29 September 2026, 15:00. SCH-5 commands
//! AV-1's Present_Value at priority 16 and defaults to 10.0; the first tick at
//! start-up writes that default. Every check below runs within milliseconds
//! of the write, long before the next 60-second tick.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::schedule::ScheduleObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::ObjectType;

fn sch5() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::SCHEDULE, 5).unwrap()
}

fn schedule(db: &mut ObjectDatabase) {
    let mut schedule = ScheduleObject::new(5, "SCH-5", PropertyValue::Real(10.0)).unwrap();
    schedule.add_object_property_reference(BACnetObjectPropertyReference::new(av1(), PV.to_raw()));
    db.add(Box::new(schedule)).unwrap();
}

/// Tuesday's daily schedule: `value` from 15:00.
fn from_three(value: f32) -> Vec<u8> {
    [&[0x0E, 0xB4, 15, 0, 0, 0][..], &real(value), &[0x0F]].concat()
}

/// A special event in effect every day: `value` from midnight, priority 1.
fn every_day(value: f32) -> Vec<u8> {
    [
        &[0x0E, 0x2B, 0xFF, 0xFF, 0xFF, 0x0F, 0x2E, 0xB4, 0, 0, 0, 0][..],
        &real(value),
        &[0x2F, 0x39, 1],
    ]
    .concat()
}

async fn start() -> Harness {
    let mut h = Harness::start_with(ServerConfig::default(), schedule).await;
    h.subscribe_cov().await;
    // The initial report carries the default the start-up tick wrote.
    assert_eq!(
        h.cov_notification().await.list_of_values[0].value,
        real(10.0)
    );
    h
}

async fn read(h: &Harness, oid: ObjectIdentifier, property: PropertyIdentifier) -> PropertyValue {
    h.server
        .database()
        .read()
        .await
        .get(&oid)
        .unwrap()
        .read_property(property, None)
        .unwrap()
}

/// AV-1's Present_Value, and the value its COV notification reports.
async fn assert_commanded(h: &Harness, value: f32) {
    assert_eq!(read(h, av1(), PV).await, PropertyValue::Real(value));
    assert_eq!(read(h, sch5(), PV).await, PropertyValue::Real(value));
    let notification = h.cov_notification().await;
    assert_eq!(notification.monitored_object_identifier, av1());
    assert_eq!(notification.list_of_values[0].value, real(value));
}

async fn write_property(
    h: &mut Harness,
    property: PropertyIdentifier,
    index: Option<u32>,
    value: Vec<u8>,
) -> Result<(), ErrorCode> {
    let mut body = BytesMut::new();
    WritePropertyRequest {
        object_identifier: sch5(),
        property_identifier: property,
        property_array_index: index,
        property_value: value,
        priority: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
        .await;
    response(h).await
}

/// Wait for the SimpleACK or Error answering the last request sent.
async fn response(h: &Harness) -> Result<(), ErrorCode> {
    let invoke_id = h.invoke_id;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let answer = {
                let mut frames = h.frames.lock().unwrap();
                let at = frames.iter().position(|apdu| match apdu {
                    Apdu::SimpleAck(ack) => ack.invoke_id == invoke_id,
                    Apdu::Error(error) => error.invoke_id == invoke_id,
                    _ => false,
                });
                at.map(|at| frames.remove(at))
            };
            match answer {
                Some(Apdu::SimpleAck(_)) => return Ok(()),
                Some(Apdu::Error(error)) => return Err(error.error_code),
                _ => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    })
    .await
    .expect("a response to the last request")
}

#[tokio::test(start_paused = true)]
async fn write_property_of_a_weekly_day_commands_the_target_at_once() {
    let mut h = start().await;
    write_property(
        &mut h,
        PropertyIdentifier::WEEKLY_SCHEDULE,
        Some(2),
        from_three(21.5),
    )
    .await
    .unwrap();
    assert_commanded(&h, 21.5).await;

    // A whole write that empties every day hands back to Schedule_Default.
    write_property(
        &mut h,
        PropertyIdentifier::WEEKLY_SCHEDULE,
        None,
        [0x0E, 0x0F].repeat(7),
    )
    .await
    .unwrap();
    assert_commanded(&h, 10.0).await;
    h.no_notification().await;
}

#[tokio::test(start_paused = true)]
async fn a_refused_write_changes_neither_the_schedule_nor_the_target() {
    let mut h = start().await;
    let before = read(&h, sch5(), PropertyIdentifier::WEEKLY_SCHEDULE).await;
    // 15:00 twice in one day.
    let duplicate = [
        &[0x0E, 0xB4, 15, 0, 0, 0][..],
        &real(21.5),
        &[0xB4, 15, 0, 0, 0],
        &real(19.0),
        &[0x0F],
    ]
    .concat();
    assert_eq!(
        write_property(
            &mut h,
            PropertyIdentifier::WEEKLY_SCHEDULE,
            Some(2),
            duplicate,
        )
        .await,
        Err(ErrorCode::DUPLICATE_ENTRY)
    );
    assert_eq!(
        read(&h, sch5(), PropertyIdentifier::WEEKLY_SCHEDULE).await,
        before
    );
    assert_eq!(read(&h, av1(), PV).await, PropertyValue::Real(10.0));
    h.no_notification().await;
}

#[tokio::test(start_paused = true)]
async fn write_property_multiple_of_exceptions_and_period_commands_the_target_at_once() {
    let mut h = start().await;
    let element = |property: PropertyIdentifier, value: Vec<u8>| BACnetPropertyValue {
        property_identifier: property,
        property_array_index: None,
        value,
        priority: None,
    };
    let mut body = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: sch5(),
            list_of_properties: vec![
                element(PropertyIdentifier::EXCEPTION_SCHEDULE, every_day(5.0)),
                // September 2026, which holds today.
                element(
                    PropertyIdentifier::EFFECTIVE_PERIOD,
                    vec![0xA4, 126, 9, 1, 2, 0xA4, 126, 9, 30, 3],
                ),
            ],
        }],
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE, body)
        .await;
    response(&h).await.unwrap();
    assert_commanded(&h, 5.0).await;

    // An Effective_Period that ends yesterday: the Schedule goes inactive,
    // Present_Value keeps its last value and nothing is written.
    write_property(
        &mut h,
        PropertyIdentifier::EFFECTIVE_PERIOD,
        None,
        vec![0xA4, 126, 9, 1, 2, 0xA4, 126, 9, 28, 1],
    )
    .await
    .unwrap();
    assert_eq!(read(&h, sch5(), PV).await, PropertyValue::Real(5.0));
    h.no_notification().await;
}

#[tokio::test(start_paused = true)]
async fn write_local_of_a_weekly_day_commands_the_target_at_once() {
    let h = start().await;
    h.server
        .write_local(
            &sch5(),
            PropertyIdentifier::WEEKLY_SCHEDULE,
            Some(2),
            PropertyValue::ApplicationData(from_three(18.0)),
            None,
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
    assert_commanded(&h, 18.0).await;
}
