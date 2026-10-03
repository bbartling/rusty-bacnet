//! SubscribeCOV reports for the Access Door, Access Point, Credential Data
//! Input and Load Control rows of the COV criteria table (Clause 13.1,
//! Table 13-1) over the wire (#1061).
//!
//! Each report carries the row's values in the row's order. A change of a
//! trigger sends a report on its own; a value that only rides along waits for
//! the next report. Access Point has no Present_Value, so its report starts
//! with Access_Event. Update_Time and the Access Point event rows have no
//! network write route, and Door_Alarm_State has one only while the door is out
//! of service (#1131), so those tests put an object holding the changed value
//! into the database (`ObjectDatabase::add` replaces by identifier) and run the
//! fanout a write commit would. The door's simulation test writes it over the
//! wire instead, as the Load Control test does Requested_Shed_Level.
//!
//! The BACnetTimeStamp, BACnetAuthenticationFactor and BACnetShedLevel values
//! go out in their Clause 21 forms (#1133). A Credential Data Input's
//! simulated Present_Value and Reliability are written over the wire while it
//! is out of service (#1168).
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::access_control::{
    AccessDoorObject, AccessPointObject, CredentialDataInputObject,
};
use bacnet_objects::load_control::LoadControlObject;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::cov::{COVNotificationRequest, SubscribeCOVRequest};
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::constructed::{
    BACnetAuthenticationFactor, BACnetAuthenticationFactorFormat, BACnetShedLevel,
};
use bacnet_types::enums::{
    AccessEvent, AuthenticationFactorType, DoorAlarmState, DoorStatus, DoorValue, LockStatus,
    ObjectType, Reliability,
};
use bacnet_types::primitives::BACnetTimeStamp;

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

/// Today at `second` past 15:00, as a BACnetTimeStamp.
fn stamp(second: u8) -> BACnetTimeStamp {
    BACnetTimeStamp::DateTime {
        date: at(0).local_date,
        time: time(second),
    }
}

/// The datetime [2] choice framed around today's Date and the Time at
/// `second` past 15:00, written out by hand.
fn stamp_bytes(second: u8) -> Vec<u8> {
    vec![0x2E, 0xA4, 126, 9, 29, 2, 0xB4, 15, 0, second, 0, 0x2F]
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

/// WriteProperty of `property` and the answer to it.
async fn try_write(
    h: &mut Harness,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    value: Vec<u8>,
) -> Result<(), ErrorCode> {
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
    response(h).await
}

async fn write(
    h: &mut Harness,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    value: Vec<u8>,
) {
    assert_eq!(
        try_write(h, oid, property, value).await,
        Ok(()),
        "write of {property:?}"
    );
}

/// One WritePropertyMultiple of `writes` to `oid`, answered with a SimpleACK.
async fn write_multiple(
    h: &mut Harness,
    oid: ObjectIdentifier,
    writes: Vec<(PropertyIdentifier, Vec<u8>)>,
) {
    let mut body = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: oid,
            list_of_properties: writes
                .into_iter()
                .map(|(property_identifier, value)| BACnetPropertyValue {
                    property_identifier,
                    property_array_index: None,
                    value,
                    priority: None,
                })
                .collect(),
        }],
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE, body)
        .await;
    assert_eq!(response(h).await, Ok(()), "WritePropertyMultiple");
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

#[tokio::test(start_paused = true)]
async fn access_door_simulated_door_alarm_state_reports_and_restores() {
    const ALARM: PropertyIdentifier = PropertyIdentifier::DOOR_ALARM_STATE;
    const OUT_OF_SERVICE: PropertyIdentifier = PropertyIdentifier::OUT_OF_SERVICE;
    let oid = ObjectIdentifier::new(ObjectType::ACCESS_DOOR, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(door(DoorAlarmState::DOOR_OPEN_TOO_LONG)).unwrap();
    })
    .await;
    let report = |alarm: DoorAlarmState, flags: Vec<u8>| {
        vec![
            (PV, enumerated(DoorValue::LOCK.to_raw())),
            (SF, flags),
            (ALARM, enumerated(alarm.to_raw())),
        ]
    };
    // Status_Flags with only OUT_OF_SERVICE set.
    let out_of_service = || vec![0x82, 0x04, 0x10];
    assert_eq!(
        subscribed(&mut h, oid).await,
        report(DoorAlarmState::DOOR_OPEN_TOO_LONG, normal())
    );

    // In service the write is refused and nothing reports.
    assert_eq!(
        try_write(
            &mut h,
            oid,
            ALARM,
            enumerated(DoorAlarmState::FORCED_OPEN.to_raw())
        )
        .await,
        Err(ErrorCode::WRITE_ACCESS_DENIED)
    );
    h.no_notification().await;

    // Out of service the OUT_OF_SERVICE flag reports, then a simulated
    // Door_Alarm_State reports on its own.
    write(
        &mut h,
        oid,
        OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(true)),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(DoorAlarmState::DOOR_OPEN_TOO_LONG, out_of_service())
    );
    write(
        &mut h,
        oid,
        ALARM,
        enumerated(DoorAlarmState::FORCED_OPEN.to_raw()),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(DoorAlarmState::FORCED_OPEN, out_of_service())
    );
    h.no_notification().await;

    // Door_Status and Lock_Status aren't in the row, so simulating them
    // alone reports nothing.
    write(
        &mut h,
        oid,
        PropertyIdentifier::DOOR_STATUS,
        enumerated(DoorStatus::OPENED.to_raw()),
    )
    .await;
    write(
        &mut h,
        oid,
        PropertyIdentifier::LOCK_STATUS,
        enumerated(LockStatus::UNLOCKED.to_raw()),
    )
    .await;
    h.no_notification().await;

    // One WritePropertyMultiple that simulates two rows reports once.
    write_multiple(
        &mut h,
        oid,
        vec![
            (
                PropertyIdentifier::DOOR_STATUS,
                enumerated(DoorStatus::CLOSED.to_raw()),
            ),
            (ALARM, enumerated(DoorAlarmState::TAMPER.to_raw())),
        ],
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(DoorAlarmState::TAMPER, out_of_service())
    );
    h.no_notification().await;

    // The return to service brings back the device's Door_Alarm_State and
    // clears the flag, in one report.
    write(
        &mut h,
        oid,
        OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(false)),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(DoorAlarmState::DOOR_OPEN_TOO_LONG, normal())
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

fn point(event: AccessEvent, tag: u64, second: u8) -> Box<dyn BACnetObject> {
    let mut point = AccessPointObject::new(1, "AP-1").unwrap();
    point.set_access_event(event, tag, stamp(second));
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
            (PropertyIdentifier::ACCESS_EVENT_TIME, stamp_bytes(second)),
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

/// CDI-1 having read the same Wiegand 26 card at `second` past 15:00.
fn reader(second: u8) -> Box<dyn BACnetObject> {
    let mut reader = CredentialDataInputObject::new(1, "CDI-1").unwrap();
    let card = BACnetAuthenticationFactor {
        format_type: AuthenticationFactorType::WIEGAND26,
        format_class: 0,
        value: vec![0x12, 0x34, 0x56],
    };
    reader.set_present_value(card, stamp(second));
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
            // format type [0] WIEGAND26, format class [1] 0, value [2].
            (PV, vec![0x09, 0x08, 0x19, 0x00, 0x2B, 0x12, 0x34, 0x56]),
            (SF, normal()),
            (PropertyIdentifier::UPDATE_TIME, stamp_bytes(second)),
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

#[tokio::test(start_paused = true)]
async fn credential_data_input_simulated_rows_report_and_restore() {
    const OUT_OF_SERVICE: PropertyIdentifier = PropertyIdentifier::OUT_OF_SERVICE;
    let oid = ObjectIdentifier::new(ObjectType::CREDENTIAL_DATA_INPUT, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        let mut reader = CredentialDataInputObject::new(1, "CDI-1").unwrap();
        reader
            .set_supported_formats([(
                BACnetAuthenticationFactorFormat::standard(AuthenticationFactorType::WIEGAND26),
                0,
            )])
            .unwrap();
        reader.set_present_value(
            BACnetAuthenticationFactor {
                format_type: AuthenticationFactorType::WIEGAND26,
                format_class: 0,
                value: vec![0x12, 0x34, 0x56],
            },
            stamp(7),
        );
        db.add(Box::new(reader)).unwrap();
    })
    .await;
    // format type [0] WIEGAND26, format class [1] 0, a three-octet value [2].
    let card = |value: [u8; 3]| [vec![0x09, 0x08, 0x19, 0x00, 0x2B], value.to_vec()].concat();
    let report = |value: [u8; 3], flags: u8, second: u8| {
        vec![
            (PV, card(value)),
            (SF, vec![0x82, 0x04, flags]),
            (PropertyIdentifier::UPDATE_TIME, stamp_bytes(second)),
        ]
    };
    let device = [0x12, 0x34, 0x56];
    let simulated = [0x65, 0x43, 0x21];
    assert_eq!(subscribed(&mut h, oid).await, report(device, 0x00, 7));

    // In service the write is refused and nothing reports.
    assert_eq!(
        try_write(&mut h, oid, PV, card(simulated)).await,
        Err(ErrorCode::WRITE_ACCESS_DENIED)
    );
    h.no_notification().await;

    // The OUT_OF_SERVICE flag reports; then a simulated read, stamped from
    // the Device clock, reports on its own.
    write(
        &mut h,
        oid,
        OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(true)),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(device, 0x10, 7)
    );
    h.set_clock(20);
    write(&mut h, oid, PV, card(simulated)).await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(simulated, 0x10, 20)
    );
    h.no_notification().await;

    // A simulated fault sets FAULT and reports; Update_Time stays.
    write(
        &mut h,
        oid,
        PropertyIdentifier::RELIABILITY,
        enumerated(Reliability::UNRELIABLE_OTHER.to_raw()),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(simulated, 0x50, 20)
    );
    h.no_notification().await;

    // Simulating the reader's own card later reports again.
    h.set_clock(25);
    write(&mut h, oid, PV, card(device)).await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(device, 0x50, 25)
    );
    h.no_notification().await;

    // The return to service brings back the reader's read, its time and
    // NO_FAULT_DETECTED, in one report.
    write(
        &mut h,
        oid,
        OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(false)),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(device, 0x00, 7)
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

/// LC-1 at requested level `requested`, achieving level 1, with the
/// Shed_Duration given.
fn load_control(requested: u64, duration: u64) -> Box<dyn BACnetObject> {
    let mut object = LoadControlObject::new(1, "LC-1").unwrap();
    object
        .set_requested_shed_level(BACnetShedLevel::Level(requested))
        .unwrap();
    object
        .set_actual_shed_level(BACnetShedLevel::Level(1))
        .unwrap();
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
    const REQUESTED: PropertyIdentifier = PropertyIdentifier::REQUESTED_SHED_LEVEL;
    let oid = ObjectIdentifier::new(ObjectType::LOAD_CONTROL, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(LoadControlObject::new(1, "LC-1").unwrap()))
            .unwrap();
    })
    .await;
    // Start_Time is a BACnetDateTime: an application Date and Time.
    let unspecified = vec![0xA4, 0xFF, 0xFF, 0xFF, 0xFF, 0xB4, 0xFF, 0xFF, 0xFF, 0xFF];
    // Duty_Window isn't served yet, so the report leaves it out. The
    // requested level goes out as its BACnetShedLevel choice.
    let report = |requested: Vec<u8>, duration: u64| {
        vec![
            (PV, enumerated(0)),
            (SF, normal()),
            (REQUESTED, requested),
            (PropertyIdentifier::START_TIME, unspecified.clone()),
            (PropertyIdentifier::SHED_DURATION, unsigned(duration)),
        ]
    };
    // level [1] 0, the LEVEL choice's default.
    assert_eq!(subscribed(&mut h, oid).await, report(vec![0x19, 0x00], 0));

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
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(vec![0x19, 0x00], 3600)
    );
    h.no_notification().await;

    // So does a Requested_Shed_Level write, as level [1] 3 and as percent
    // [0] 80.
    for requested in [vec![0x19, 0x03], vec![0x09, 0x50]] {
        write(&mut h, oid, REQUESTED, requested.clone()).await;
        assert_eq!(
            values(&h.cov_notification().await, oid),
            report(requested, 3600)
        );
        h.no_notification().await;
    }

    // A level the application sets reports the same way.
    h.replace_and_fan_out(load_control(5, 3600)).await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(vec![0x19, 0x05], 3600)
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

/// The three shed levels of `oid`, encoded as ReadProperty serves them.
async fn shed_levels(h: &Harness, oid: ObjectIdentifier) -> [Vec<u8>; 3] {
    let db = h.server.database().read().await;
    let object = db.get(&oid).unwrap();
    [
        PropertyIdentifier::REQUESTED_SHED_LEVEL,
        PropertyIdentifier::EXPECTED_SHED_LEVEL,
        PropertyIdentifier::ACTUAL_SHED_LEVEL,
    ]
    .map(|p| encode(object.read_property(p, None).unwrap()))
}

#[tokio::test(start_paused = true)]
async fn load_control_requested_shed_level_write_takes_the_choice_form() {
    const REQUESTED: PropertyIdentifier = PropertyIdentifier::REQUESTED_SHED_LEVEL;
    let oid = ObjectIdentifier::new(ObjectType::LOAD_CONTROL, 1).unwrap();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(LoadControlObject::new(1, "LC-1").unwrap()))
            .unwrap();
    })
    .await;
    // amount [2] 12.5 kW. The object stays SHED_INACTIVE, so Expected and
    // Actual take the AMOUNT default, 0.0.
    let amount = vec![0x2C, 0x41, 0x48, 0x00, 0x00];
    let zero_kw = vec![0x2C, 0x00, 0x00, 0x00, 0x00];
    let after = [amount.clone(), zero_kw.clone(), zero_kw];
    write(&mut h, oid, REQUESTED, amount).await;
    assert_eq!(shed_levels(&h, oid).await, after);

    // The application-tagged forms served before #1133, and a context tag
    // the CHOICE lacks, are the wrong datatype; asking for more load than
    // the baseline is out of range. Nothing changes.
    for (value, code) in [
        (unsigned(50), ErrorCode::INVALID_DATA_TYPE),
        (
            encode(PropertyValue::Real(12.5)),
            ErrorCode::INVALID_DATA_TYPE,
        ),
        (vec![0x39, 0x01], ErrorCode::INVALID_DATA_TYPE),
        // percent [0] 101
        (vec![0x09, 0x65], ErrorCode::VALUE_OUT_OF_RANGE),
        // amount [2] -1.0
        (
            vec![0x2C, 0xBF, 0x80, 0x00, 0x00],
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
    ] {
        assert_eq!(try_write(&mut h, oid, REQUESTED, value).await, Err(code));
        assert_eq!(shed_levels(&h, oid).await, after);
    }
    h.server.stop().await.unwrap();
}
