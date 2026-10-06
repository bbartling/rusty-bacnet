//! The application's routes to the access-control inputs (#1132):
//! `report_access_event_local`, `report_credential_read_local` and
//! `report_door_state_local`. Each takes its record as one local write, so
//! the Table 13-1 report and the event pass follow it, stamps a missing time
//! from the Device clock, and refuses an input while the object's
//! Out_Of_Service is TRUE, changing nothing and reporting nothing.

use super::*;
use bacnet_types::enums::{DoorStatus, EventState, LockStatus};

fn ap(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ACCESS_POINT, instance).unwrap()
}

fn cdi() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::CREDENTIAL_DATA_INPUT, 1).unwrap()
}

fn door_oid() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ACCESS_DOOR, 1).unwrap()
}

fn assert_refused(result: Result<(), Error>, class: ErrorClass, code: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class: c, code: e })
            if c == class.to_raw() as u32 && e == code.to_raw() as u32),
        "expected {class:?} / {code:?}, got {result:?}"
    );
}

/// What `oid` serves for `property`, encoded.
async fn served(h: &Harness, oid: ObjectIdentifier, property: PropertyIdentifier) -> Vec<u8> {
    let db = h.server.database().read().await;
    encode(db.get(&oid).unwrap().read_property(property, None).unwrap())
}

#[tokio::test(start_paused = true)]
async fn access_event_route_stamps_the_clock_and_refuses_out_of_service() {
    const EVENT: PropertyIdentifier = PropertyIdentifier::ACCESS_EVENT;
    let oid = ap(1);
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(point(AccessEvent::GRANTED, 1, 7)).unwrap();
    })
    .await;
    subscribed(&mut h, oid).await;

    // An event with no time takes the Device clock's, and with no credential
    // or factor the no-credential reference and the UNDEFINED factor.
    h.set_clock(20);
    let unknown = AccessEventReport::new(AccessEvent::DENIED_UNKNOWN_CREDENTIAL, 2);
    h.server
        .report_access_event_local(&oid, unknown)
        .await
        .unwrap();
    let report = |event: AccessEvent, flags: u8, tag: u64, second: u8| {
        vec![
            (EVENT, enumerated(event.to_raw())),
            (SF, vec![0x82, 0x04, flags]),
            (PropertyIdentifier::ACCESS_EVENT_TAG, unsigned(tag)),
            (PropertyIdentifier::ACCESS_EVENT_TIME, stamp_bytes(second)),
            (
                PropertyIdentifier::ACCESS_EVENT_CREDENTIAL,
                no_credential_bytes(),
            ),
            (
                PropertyIdentifier::ACCESS_EVENT_AUTHENTICATION_FACTOR,
                undefined_factor_bytes(),
            ),
        ]
    };
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(AccessEvent::DENIED_UNKNOWN_CREDENTIAL, 0x00, 2, 20)
    );

    // A credential reference to another object type is refused whole.
    h.set_clock(25);
    let not_a_credential = AccessEventReport {
        credential: Some(ap(2).into()),
        ..AccessEventReport::new(AccessEvent::GRANTED, 3)
    };
    assert_refused(
        h.server
            .report_access_event_local(&oid, not_a_credential)
            .await,
        ErrorClass::PROPERTY,
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    h.no_notification().await;

    // Out of service the point performs no authentication, so an event is
    // refused and changes nothing (Clause 12.31.8); the edge's own event
    // stays served.
    write(
        &mut h,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(true)),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(AccessEvent::OUT_OF_SERVICE, 0x10, 3, 25)
    );
    h.set_clock(30);
    assert_refused(
        h.server
            .report_access_event_local(&oid, access_event(AccessEvent::GRANTED, 4, 30))
            .await,
        ErrorClass::PROPERTY,
        ErrorCode::WRITE_ACCESS_DENIED,
    );
    h.no_notification().await;
    assert_eq!(
        served(&h, oid, EVENT).await,
        enumerated(AccessEvent::OUT_OF_SERVICE.to_raw())
    );

    // Back in service the route takes events again.
    write(
        &mut h,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(false)),
    )
    .await;
    h.cov_notification().await;
    h.set_clock(35);
    h.server
        .report_access_event_local(&oid, AccessEventReport::new(AccessEvent::GRANTED, 5))
        .await
        .unwrap();
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(AccessEvent::GRANTED, 0x00, 5, 35)
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn credential_read_route_stamps_the_clock_and_refuses_out_of_service() {
    let oid = cdi();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(reader(7)).unwrap();
    })
    .await;
    let report = |value: Vec<u8>, flags: u8, second: u8| {
        vec![
            (PV, value),
            (SF, vec![0x82, 0x04, flags]),
            (PropertyIdentifier::UPDATE_TIME, stamp_bytes(second)),
        ]
    };
    assert_eq!(subscribed(&mut h, oid).await, report(card_bytes(), 0x00, 7));

    // A read with no time takes the Device clock's, so the same card read
    // again still moves Update_Time and reports.
    for second in [20, 25] {
        h.set_clock(second);
        h.server
            .report_credential_read_local(&oid, CredentialReadReport::new(card()))
            .await
            .unwrap();
        assert_eq!(
            values(&h.cov_notification().await, oid),
            report(card_bytes(), 0x00, second)
        );
    }

    // A format the reader doesn't declare is refused (Clause 12.36.4).
    let wiegand37 = BACnetAuthenticationFactor {
        format_type: AuthenticationFactorType::WIEGAND37,
        ..card()
    };
    assert_refused(
        h.server
            .report_credential_read_local(&oid, CredentialReadReport::new(wiegand37))
            .await,
        ErrorClass::PROPERTY,
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    h.no_notification().await;

    // Out of service a client may be simulating the reader, so a read is
    // refused; the return to service serves the reader's last read again.
    write(
        &mut h,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(true)),
    )
    .await;
    h.cov_notification().await;
    h.set_clock(30);
    assert_refused(
        h.server
            .report_credential_read_local(&oid, CredentialReadReport::new(card()))
            .await,
        ErrorClass::PROPERTY,
        ErrorCode::WRITE_ACCESS_DENIED,
    );
    h.no_notification().await;
    write(
        &mut h,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(false)),
    )
    .await;
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(card_bytes(), 0x00, 25)
    );
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn door_state_route_runs_the_event_pass_and_refuses_out_of_service() {
    const ALARM: PropertyIdentifier = PropertyIdentifier::DOOR_ALARM_STATE;
    let oid = door_oid();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        // Event detection on: FORCED_OPEN is an alarm value with no delay.
        let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
        door.set_alarm_values([DoorAlarmState::FORCED_OPEN])
            .unwrap();
        db.add(Box::new(door)).unwrap();
    })
    .await;
    let report = |alarm: DoorAlarmState, flags: u8| {
        vec![
            (PV, enumerated(DoorValue::LOCK.to_raw())),
            (SF, vec![0x82, 0x04, flags]),
            (ALARM, enumerated(alarm.to_raw())),
        ]
    };
    assert_eq!(
        subscribed(&mut h, oid).await,
        report(DoorAlarmState::NORMAL, 0x00)
    );

    // The event pass after the report puts the door in alarm at once, with
    // no tick, and the one report carries IN_ALARM.
    let forced = DoorStateReport {
        door_status: Some(DoorStatus::OPENED),
        lock_status: Some(LockStatus::LOCKED),
        door_alarm_state: Some(DoorAlarmState::FORCED_OPEN),
    };
    h.server
        .report_door_state_local(&oid, forced)
        .await
        .unwrap();
    assert_eq!(
        values(&h.cov_notification().await, oid),
        report(DoorAlarmState::FORCED_OPEN, 0x80)
    );
    h.no_notification().await;
    assert_eq!(
        served(&h, oid, PropertyIdentifier::EVENT_STATE).await,
        enumerated(EventState::OFFNORMAL.to_raw())
    );
    assert_eq!(
        served(&h, oid, PropertyIdentifier::DOOR_STATUS).await,
        enumerated(DoorStatus::OPENED.to_raw())
    );

    // A report is taken whole or not at all: a reserved Door_Status, or an
    // alarm state the lists don't admit, refuses the other values too.
    for refused in [
        DoorStateReport {
            door_status: Some(DoorStatus::from_raw(1000)),
            door_alarm_state: Some(DoorAlarmState::NORMAL),
            ..DoorStateReport::default()
        },
        DoorStateReport {
            door_status: Some(DoorStatus::CLOSED),
            door_alarm_state: Some(DoorAlarmState::TAMPER),
            ..DoorStateReport::default()
        },
    ] {
        assert_refused(
            h.server.report_door_state_local(&oid, refused).await,
            ErrorClass::PROPERTY,
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
    }
    h.no_notification().await;
    assert_eq!(
        served(&h, oid, PropertyIdentifier::DOOR_STATUS).await,
        enumerated(DoorStatus::OPENED.to_raw())
    );

    // Out of service a client may be simulating the door, so a report is
    // refused and the door keeps what it served.
    write(
        &mut h,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        encode(PropertyValue::Boolean(true)),
    )
    .await;
    h.cov_notification().await;
    let closed = DoorStateReport {
        door_status: Some(DoorStatus::CLOSED),
        door_alarm_state: Some(DoorAlarmState::NORMAL),
        ..DoorStateReport::default()
    };
    assert_refused(
        h.server.report_door_state_local(&oid, closed).await,
        ErrorClass::PROPERTY,
        ErrorCode::WRITE_ACCESS_DENIED,
    );
    h.no_notification().await;
    assert_eq!(
        served(&h, oid, ALARM).await,
        enumerated(DoorAlarmState::FORCED_OPEN.to_raw())
    );
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn routes_refuse_other_objects() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(point(AccessEvent::GRANTED, 1, 7)).unwrap();
        db.add(reader(7)).unwrap();
        db.add(Box::new(AccessDoorObject::new(1, "DOOR-1").unwrap()))
            .unwrap();
    })
    .await;
    let analog_value = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap();
    let event = || AccessEventReport::new(AccessEvent::GRANTED, 2);
    let read = || CredentialReadReport::new(card());
    for result in [
        h.server
            .report_access_event_local(&door_oid(), event())
            .await,
        h.server.report_access_event_local(&cdi(), event()).await,
        h.server.report_credential_read_local(&ap(1), read()).await,
        h.server
            .report_credential_read_local(&analog_value, read())
            .await,
        h.server
            .report_door_state_local(&ap(1), DoorStateReport::default())
            .await,
    ] {
        assert_refused(
            result,
            ErrorClass::OBJECT,
            ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
        );
    }
    assert_refused(
        h.server.report_access_event_local(&ap(9), event()).await,
        ErrorClass::OBJECT,
        ErrorCode::UNKNOWN_OBJECT,
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
