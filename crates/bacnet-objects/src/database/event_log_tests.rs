//! `ObjectDatabase::log_event_notification`: each Event Log takes the
//! device's own notifications through its lifecycle (#1275).
use super::*;
use crate::analog::AnalogValueObject;
use crate::clock::{ClockFrame, ClockReader};
use crate::device::{DeviceConfig, DeviceObject};
use crate::event_enrollment::EventEnrollmentObject;
use crate::event_log::EventLogObject;
use crate::traits::BACnetObject;
use bacnet_types::bitstring::LogStatus;
use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use bacnet_types::enums::{EventState, EventType, NotifyType, PropertyIdentifier};
use bacnet_types::primitives::{BACnetTimeStamp, Date, ObjectIdentifier, PropertyValue, Time};
use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct FixedClock(ClockFrame);

impl ClockReader for FixedClock {
    fn read_clock(&self) -> Option<ClockFrame> {
        Some(self.0)
    }
}

const DATE: Date = Date {
    year: 126,
    month: 9,
    day: 29,
    day_of_week: 2,
};

const TIME: Time = Time {
    hour: 15,
    minute: 4,
    second: 5,
    hundredths: 6,
};

fn frame() -> ClockFrame {
    ClockFrame {
        local_date: DATE,
        local_time: TIME,
        utc_offset: 0,
        daylight_savings_status: false,
    }
}

fn log_oid(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::EVENT_LOG, instance).unwrap()
}

/// A database on a valid clock holding AV-1 and Event Logs `logs`, each
/// with room for `buffer_size` records.
fn database(logs: &[u32], buffer_size: u32) -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    db.set_clock_reader(Some(Arc::new(FixedClock(frame()))));
    db.add(Box::new(AnalogValueObject::new(1, "AV-1", 62).unwrap()))
        .unwrap();
    for &instance in logs {
        db.add(Box::new(
            EventLogObject::new(instance, format!("EL-{instance}"), buffer_size).unwrap(),
        ))
        .unwrap();
    }
    db
}

/// AV-1's alarm, as the server builds it before any recipient's process
/// identifier is filled in.
fn alarm(event_object: ObjectIdentifier) -> EventNotificationRequest {
    EventNotificationRequest {
        process_identifier: 0,
        initiating_device_identifier: ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap(),
        event_object_identifier: event_object,
        timestamp: BACnetTimeStamp::SequenceNumber(3),
        notification_class: 0,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: Some("high".into()),
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    }
}

fn av1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap()
}

/// The records `log` holds, through its `records()`.
fn records(db: &mut ObjectDatabase, log: ObjectIdentifier) -> Vec<BACnetEventLogRecord> {
    let object = db
        .objects
        .get_mut(&log)
        .unwrap()
        .as_mut()
        .as_stored_any_mut(crate::traits::ObjectStorageAccess(()))
        .downcast_mut::<EventLogObject>()
        .unwrap();
    object.records().iter().cloned().collect()
}

fn notification_record(notification: EventNotificationRequest) -> BACnetEventLogRecord {
    BACnetEventLogRecord {
        date: DATE,
        time: TIME,
        log_datum: EventLogDatum::Notification(notification),
    }
}

fn status_record(status: LogStatus) -> BACnetEventLogRecord {
    BACnetEventLogRecord {
        date: DATE,
        time: TIME,
        log_datum: EventLogDatum::LogStatus(status),
    }
}

#[test]
fn every_event_log_records_the_notification_at_the_device_clock_time() {
    let mut db = database(&[1, 2], 8);
    db.log_event_notification(&alarm(av1()));
    for log in [log_oid(1), log_oid(2)] {
        assert_eq!(records(&mut db, log), [notification_record(alarm(av1()))]);
    }
}

#[test]
fn a_notification_about_an_event_log_goes_in_no_log() {
    let mut db = database(&[1, 2], 8);
    db.log_event_notification(&alarm(log_oid(1)));
    for log in [log_oid(1), log_oid(2)] {
        assert!(records(&mut db, log).is_empty());
    }
}

/// Event Enrollment `instance` monitoring `property` of `object`, its
/// reference naming `device` when given.
fn enrollment(
    instance: u32,
    object: ObjectIdentifier,
    property: PropertyIdentifier,
    device: Option<u32>,
) -> EventEnrollmentObject {
    let mut enrollment = EventEnrollmentObject::new(
        instance,
        format!("EE-{instance}"),
        EventType::CHANGE_OF_VALUE,
    )
    .unwrap();
    let mut reference = BACnetDeviceObjectPropertyReference::new_local(object, property.to_raw());
    reference.device_identifier =
        device.map(|instance| ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap());
    enrollment
        .set_object_property_reference(Some(reference))
        .unwrap();
    enrollment
}

fn ee(instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::EVENT_ENROLLMENT, instance).unwrap()
}

#[test]
fn an_enrollment_notification_about_any_local_event_log_goes_in_no_log() {
    let mut db = database(&[1, 2], 8);
    db.add(Box::new(
        DeviceObject::new(DeviceConfig {
            instance: 7,
            name: "Device-7".into(),
            ..DeviceConfig::default()
        })
        .unwrap(),
    ))
    .unwrap();
    let count = PropertyIdentifier::TOTAL_RECORD_COUNT;
    db.add(Box::new(enrollment(1, log_oid(1), count, None)))
        .unwrap();
    db.add(Box::new(enrollment(2, log_oid(2), count, Some(7))))
        .unwrap();
    // Another device's Event Log 1, and an analog value here.
    db.add(Box::new(enrollment(3, log_oid(1), count, Some(8))))
        .unwrap();
    db.add(Box::new(enrollment(
        4,
        av1(),
        PropertyIdentifier::PRESENT_VALUE,
        None,
    )))
    .unwrap();
    for instance in 1..=4 {
        db.log_event_notification(&alarm(ee(instance)));
    }
    // EE-1 and EE-2 watch EL-1 and EL-2: neither log takes either report.
    for log in [log_oid(1), log_oid(2)] {
        assert_eq!(
            records(&mut db, log),
            [3, 4].map(|instance| notification_record(alarm(ee(instance))))
        );
    }
}

#[test]
fn nothing_is_logged_without_a_valid_device_clock() {
    // 2026-09-29 is a Tuesday, not a Wednesday.
    let mut invalid = frame();
    invalid.local_date.day_of_week = 3;
    for clock in [None, Some(invalid)] {
        let mut db = database(&[1], 8);
        db.set_clock_reader(clock.map(|frame| Arc::new(FixedClock(frame)) as Arc<dyn ClockReader>));
        db.log_event_notification(&alarm(av1()));
        assert!(records(&mut db, log_oid(1)).is_empty());
    }
}

#[test]
fn a_disabled_log_ignores_the_notification() {
    let mut db = database(&[1, 2], 8);
    db.get_mut(&log_oid(1))
        .unwrap()
        .write_property(
            PropertyIdentifier::LOG_ENABLE,
            None,
            PropertyValue::Boolean(false),
            None,
        )
        .unwrap();
    db.log_event_notification(&alarm(av1()));
    assert_eq!(
        records(&mut db, log_oid(1)),
        [status_record(LogStatus::LOG_DISABLED)],
        "only the disable itself is recorded"
    );
    assert_eq!(
        records(&mut db, log_oid(2)),
        [notification_record(alarm(av1()))]
    );
}

#[test]
fn stop_when_full_stops_the_log_before_it_fills() {
    let mut db = database(&[1], 2);
    db.get_mut(&log_oid(1))
        .unwrap()
        .write_property(
            PropertyIdentifier::STOP_WHEN_FULL,
            None,
            PropertyValue::Boolean(true),
            None,
        )
        .unwrap();
    for _ in 0..3 {
        db.log_event_notification(&alarm(av1()));
    }
    assert_eq!(
        records(&mut db, log_oid(1)),
        [
            notification_record(alarm(av1())),
            status_record(LogStatus::LOG_DISABLED),
        ]
    );
    assert_eq!(
        db.get(&log_oid(1))
            .unwrap()
            .read_property(PropertyIdentifier::LOG_ENABLE, None)
            .unwrap(),
        PropertyValue::Boolean(false)
    );
}

/// An Event Log type object that refuses every record and counts the tries.
struct Refusing(Arc<AtomicUsize>);

impl BACnetObject for Refusing {
    fn object_identifier(&self) -> ObjectIdentifier {
        log_oid(3)
    }
    fn object_name(&self) -> &str {
        "EL-3"
    }
    fn read_property(&self, _: PropertyIdentifier, _: Option<u32>) -> Result<PropertyValue, Error> {
        Err(crate::common::unknown_property_error())
    }
    fn write_property(
        &mut self,
        _: PropertyIdentifier,
        _: Option<u32>,
        _: PropertyValue,
        _: Option<u8>,
    ) -> Result<(), Error> {
        Err(crate::common::unknown_property_error())
    }
    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        Cow::Borrowed(&[])
    }
    fn add_event_log_record(&mut self, _: BACnetEventLogRecord) -> Result<(), Error> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(Error::Protocol {
            class: ErrorClass::DEVICE.to_raw() as u32,
            code: ErrorCode::OPERATIONAL_PROBLEM.to_raw() as u32,
        })
    }
}

#[test]
fn a_log_that_refuses_the_record_leaves_the_others_logging() {
    let mut db = database(&[1, 2], 8);
    let tries = Arc::new(AtomicUsize::new(0));
    db.add(Box::new(Refusing(Arc::clone(&tries)))).unwrap();
    db.log_event_notification(&alarm(av1()));
    assert_eq!(tries.load(Ordering::Relaxed), 1);
    for log in [log_oid(1), log_oid(2)] {
        assert_eq!(records(&mut db, log), [notification_record(alarm(av1()))]);
    }
}
