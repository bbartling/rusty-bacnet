//! SubscribeCOV reports for the Access Door, Access Point, Credential Data
//! Input and Load Control rows of the COV criteria table (Clause 13.1,
//! Table 13-1) over the wire (#1061).
//!
//! Each report carries the row's values in the row's order. A change of a
//! trigger sends a report on its own; a value that only rides along waits for
//! the next report. Access Point has no Present_Value, so its report starts
//! with Access_Event. Door_Alarm_State, Update_Time and the Access Point event
//! rows have no network write route, so those tests put an object holding the
//! changed value into the database (`ObjectDatabase::add` replaces by
//! identifier) and run the fanout a write commit would.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::access_control::{
    AccessDoorObject, AccessPointObject, CredentialDataInputObject,
};
use bacnet_objects::load_control::LoadControlObject;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::cov::{COVNotificationRequest, SubscribeCOVRequest};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::constructed::BACnetShedLevel;
use bacnet_types::enums::{AccessEvent, DoorAlarmState, DoorValue, ObjectType};
use bacnet_types::primitives::{Date, Time};

type Values = Vec<(PropertyIdentifier, Vec<u8>)>;

fn encode(value: PropertyValue) -> Vec<u8> {
    let mut encoded = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut encoded, &value).unwrap();
    encoded.to_vec()
}

fn enumerated(value: u32) -> Vec<u8> {
    encode(PropertyValue::Enumerated(value))
}

fn unsigned(value: u64) -> Vec<u8> {
    encode(PropertyValue::Unsigned(value))
}

/// Status_Flags with every flag clear.
fn normal() -> Vec<u8> {
    vec![0x82, 0x04, 0x00]
}

/// A date and time as the objects here serve them: Date, then Time.
fn stamp(date: Date, time: Time) -> Vec<u8> {
    encode(PropertyValue::List(vec![
        PropertyValue::Date(date),
        PropertyValue::Time(time),
    ]))
}

fn today() -> Date {
    at(0).local_date
}

/// `(property, value bytes)` of a notification for `oid`, in wire order.
fn values(notification: &COVNotificationRequest, oid: ObjectIdentifier) -> Values {
    assert_eq!(notification.monitored_object_identifier, oid);
    notification
        .list_of_values
        .iter()
        .map(|value| {
            assert_eq!(value.property_array_index, None);
            assert_eq!(value.priority, None);
            (value.property_identifier, value.value.clone())
        })
        .collect()
}

/// SubscribeCOV for `oid` and the answer to it.
async fn subscribe(h: &mut Harness, oid: ObjectIdentifier) -> Result<(), ErrorCode> {
    let mut body = BytesMut::new();
    SubscribeCOVRequest {
        subscriber_process_identifier: 1061,
        monitored_object_identifier: oid,
        issue_confirmed_notifications: Some(false),
        lifetime: Some(300),
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::SUBSCRIBE_COV, body).await;
    response(h).await
}

/// Subscribe to `oid` and return the values of the first report.
async fn subscribed(h: &mut Harness, oid: ObjectIdentifier) -> Values {
    assert_eq!(subscribe(h, oid).await, Ok(()), "SubscribeCOV on {oid:?}");
    values(&h.cov_notification().await, oid)
}

async fn write(
    h: &mut Harness,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    value: Vec<u8>,
) {
    let mut body = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: None,
        property_value: value,
        priority: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
        .await;
    assert_eq!(response(h).await, Ok(()), "write of {property:?}");
}

fn door(alarm: DoorAlarmState) -> Box<dyn BACnetObject> {
    let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
    door.set_door_alarm_state(alarm);
    Box::new(door)
}

#[tokio::test(start_paused = true)]
async fn access_door_cov_reports_and_triggers_on_door_alarm_state() {
    let oid = ObjectIdentifier::new(ObjectType::ACCESS_DOOR, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(door(DoorAlarmState::NORMAL)).unwrap();
    })
    .await;
    let report = |alarm: DoorAlarmState| {
        vec![
            (PV, enumerated(DoorValue::LOCK.to_raw())),
            (SF, normal()),
            (
                PropertyIdentifier::DOOR_ALARM_STATE,
                enumerated(alarm.to_raw()),
            ),
        ]
    };
    assert_eq!(
        subscribed(&mut h, oid).await,
        report(DoorAlarmState::NORMAL)
    );

    // A Door_Alarm_State change alone sends a report.
    h.replace_and_fan_out(door(DoorAlarmState::FORCED_OPEN))
        .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(DoorAlarmState::FORCED_OPEN)
    );
    h.no_notification().await;

    // Row values unchanged: neither a fanout nor a pulse-time write reports.
    h.replace_and_fan_out(door(DoorAlarmState::FORCED_OPEN))
        .await;
    write(
        &mut h,
        oid,
        PropertyIdentifier::DOOR_PULSE_TIME,
        unsigned(20),
    )
    .await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

fn point(event: AccessEvent, tag: u64, second: u8) -> Box<dyn BACnetObject> {
    let mut point = AccessPointObject::new(1, "AP-1").unwrap();
    point.set_access_event(event, tag, today(), time(second));
    Box::new(point)
}

#[tokio::test(start_paused = true)]
async fn access_point_cov_leads_with_access_event_and_triggers_on_its_time() {
    let oid = ObjectIdentifier::new(ObjectType::ACCESS_POINT, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(point(AccessEvent::GRANTED, 1, 7)).unwrap();
    })
    .await;
    // Access_Event_Credential and Access_Event_Authentication_Factor aren't
    // served yet, so the report leaves them out.
    let report = |event: AccessEvent, tag: u64, second: u8| {
        vec![
            (PropertyIdentifier::ACCESS_EVENT, enumerated(event.to_raw())),
            (SF, normal()),
            (PropertyIdentifier::ACCESS_EVENT_TAG, unsigned(tag)),
            (
                PropertyIdentifier::ACCESS_EVENT_TIME,
                stamp(today(), time(second)),
            ),
        ]
    };
    assert_eq!(
        subscribed(&mut h, oid).await,
        report(AccessEvent::GRANTED, 1, 7)
    );

    // Access_Event and Access_Event_Tag only ride along.
    h.replace_and_fan_out(point(AccessEvent::DENIED_DENY_ALL, 2, 7))
        .await;
    h.no_notification().await;

    // A new Access_Event_Time sends a report with the current values.
    h.replace_and_fan_out(point(AccessEvent::GRANTED, 3, 9))
        .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(AccessEvent::GRANTED, 3, 9)
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

fn reader(second: u8) -> Box<dyn BACnetObject> {
    let mut reader = CredentialDataInputObject::new(1, "CDI-1").unwrap();
    reader.set_update_time(today(), time(second));
    Box::new(reader)
}

#[tokio::test(start_paused = true)]
async fn credential_data_input_cov_reports_and_triggers_on_update_time() {
    let oid = ObjectIdentifier::new(ObjectType::CREDENTIAL_DATA_INPUT, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(reader(7)).unwrap();
    })
    .await;
    let report = |second: u8| {
        vec![
            (PV, enumerated(0)),
            (SF, normal()),
            (
                PropertyIdentifier::UPDATE_TIME,
                stamp(today(), time(second)),
            ),
        ]
    };
    assert_eq!(subscribed(&mut h, oid).await, report(7));

    // The same input read again moves Update_Time alone, and that reports.
    h.replace_and_fan_out(reader(9)).await;
    assert_eq!(values(&h.cov_notification().await, oid), report(9));
    h.no_notification().await;

    // Row values unchanged: a Description write doesn't report.
    write(
        &mut h,
        oid,
        PropertyIdentifier::DESCRIPTION,
        encode(PropertyValue::CharacterString("lobby reader".into())),
    )
    .await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

/// LC-1 shedding 20 percent, with the requested level and Shed_Duration given.
fn load_control(requested: u32, duration: u64) -> Box<dyn BACnetObject> {
    let mut object = LoadControlObject::new(1, "LC-1").unwrap();
    object.set_requested_shed_level(BACnetShedLevel::Percent(requested));
    object.set_actual_shed_level(BACnetShedLevel::Percent(20));
    object
        .write_property(
            PropertyIdentifier::SHED_DURATION,
            None,
            PropertyValue::Unsigned(duration),
            None,
        )
        .unwrap();
    Box::new(object)
}

#[tokio::test(start_paused = true)]
async fn load_control_cov_reports_and_triggers_on_its_shed_rows() {
    let oid = ObjectIdentifier::new(ObjectType::LOAD_CONTROL, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(LoadControlObject::new(1, "LC-1").unwrap()))
            .unwrap();
    })
    .await;
    let unspecified = stamp(
        Date {
            year: 0xFF,
            month: 0xFF,
            day: 0xFF,
            day_of_week: 0xFF,
        },
        Time {
            hour: 0xFF,
            minute: 0xFF,
            second: 0xFF,
            hundredths: 0xFF,
        },
    );
    // Duty_Window isn't served yet, so the report leaves it out.
    let report = |requested: u64, duration: u64| {
        vec![
            (PV, enumerated(0)),
            (SF, normal()),
            (
                PropertyIdentifier::REQUESTED_SHED_LEVEL,
                encode(PropertyValue::List(vec![PropertyValue::Unsigned(
                    requested,
                )])),
            ),
            (PropertyIdentifier::START_TIME, unspecified.clone()),
            (PropertyIdentifier::SHED_DURATION, unsigned(duration)),
        ]
    };
    assert_eq!(subscribed(&mut h, oid).await, report(0, 0));

    // Actual_Shed_Level isn't in the row, so its change doesn't report.
    h.replace_and_fan_out(load_control(0, 0)).await;
    h.no_notification().await;

    // A Shed_Duration write sends a report.
    write(
        &mut h,
        oid,
        PropertyIdentifier::SHED_DURATION,
        unsigned(3600),
    )
    .await;
    assert_eq!(values(&h.cov_notification().await, oid), report(0, 3600));
    h.no_notification().await;

    // So does a Requested_Shed_Level change. The network write of that row
    // doesn't decode yet, so the change comes from the application.
    h.replace_and_fan_out(load_control(50, 3600)).await;
    assert_eq!(values(&h.cov_notification().await, oid), report(50, 3600));
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
