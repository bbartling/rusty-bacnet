//! Trend Log Multiple polling: one value per member in each record (#1203).

use super::*;
use crate::analog::{AnalogOutputObject, AnalogValueObject};
use crate::trend::TrendLogMultipleObject;
use bacnet_encoding::constructed::decode_log_multiple_record;
use bacnet_types::constructed::BACnetLogMultipleRecord;

const THIS_DEVICE: u32 = 100;

/// AV-1 at 42.5, AO-1 holding 61.5 at priority 8, and Device 100, with the
/// fixture's clocks and no Trend Log.
fn database() -> (ObjectDatabase, Arc<Mutex<Duration>>) {
    let (mut db, trend, time, _) = fixture(u32::MAX);
    db.remove(&trend).unwrap();
    db.remove(&target()).unwrap();
    let mut av = AnalogValueObject::new(1, "AV", 95).unwrap();
    av.set_relinquish_default(42.5).unwrap();
    db.add(Box::new(av)).unwrap();
    let mut ao = AnalogOutputObject::new(1, "AO", 95).unwrap();
    ao.write_property_from(
        P::PRESENT_VALUE,
        None,
        PropertyValue::Real(61.5),
        Some(8),
        &crate::command_source::test_origin(),
    )
    .unwrap();
    db.add(Box::new(ao)).unwrap();
    db.add(Box::new(
        crate::device::DeviceObject::new(crate::device::DeviceConfig {
            instance: THIS_DEVICE,
            name: "Device".into(),
            ..Default::default()
        })
        .unwrap(),
    ))
    .unwrap();
    (db, time)
}

fn av() -> ObjectIdentifier {
    target()
}

fn ao() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 1).unwrap()
}

fn member(
    object: ObjectIdentifier,
    property: P,
    index: Option<u32>,
    device: Option<u32>,
) -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference {
        object_identifier: object,
        property_identifier: property.to_raw(),
        property_array_index: index,
        device_identifier: device
            .map(|instance| ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap()),
    }
}

fn multiple(
    interval: u32,
    capacity: u32,
    members: Vec<BACnetDeviceObjectPropertyReference>,
) -> TrendLogMultipleObject {
    let mut log = TrendLogMultipleObject::new(1, "TLM", capacity).unwrap();
    for member in members {
        log.add_property_reference(member);
    }
    log.write_property(
        P::LOG_INTERVAL,
        None,
        PropertyValue::Unsigned(interval.into()),
        None,
    )
    .unwrap();
    log
}

/// The log's records, decoded from the framed Log_Buffer a read serves.
fn records(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<BACnetLogMultipleRecord> {
    let PropertyValue::List(items) = db
        .get(&oid)
        .unwrap()
        .read_property(P::LOG_BUFFER, None)
        .unwrap()
    else {
        panic!("Log_Buffer is a list")
    };
    items
        .iter()
        .map(|item| {
            let PropertyValue::ApplicationData(bytes) = item else {
                panic!("each record is framed: {item:?}")
            };
            let (record, end) = decode_log_multiple_record(bytes, 0).unwrap();
            assert_eq!(end, bytes.len());
            record
        })
        .collect()
}

/// The values of the one record a single poll of `members` logs.
fn polled(members: Vec<BACnetDeviceObjectPropertyReference>) -> Vec<LogValue> {
    let (mut db, _) = database();
    let log = multiple(u32::MAX, 8, members);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    db.poll_trend_logs();
    let records = records(&db, oid);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].date, frame().local_date);
    assert_eq!(records[0].time, frame().local_time);
    let LogData::Values(values) = &records[0].log_data else {
        panic!("a sample, not {:?}", records[0].log_data)
    };
    values.clone()
}

fn failed(class: ErrorClass, code: ErrorCode) -> LogValue {
    LogValue::Failure {
        error_class: class.to_raw().into(),
        error_code: code.to_raw().into(),
    }
}

#[test]
fn every_local_member_is_sampled_into_one_record_in_member_order() {
    assert_eq!(
        polled(vec![
            member(av(), P::PRESENT_VALUE, None, None),
            member(ao(), P::PRESENT_VALUE, None, Some(THIS_DEVICE)),
            member(av(), P::OUT_OF_SERVICE, None, None),
            member(av(), P::UNITS, None, None),
        ]),
        vec![
            LogValue::RealValue(42.5),
            LogValue::RealValue(61.5),
            LogValue::BooleanValue(false),
            LogValue::EnumValue(95),
        ]
    );
}

#[test]
fn a_failing_member_logs_its_error_beside_the_other_values() {
    let missing = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 9).unwrap();
    assert_eq!(
        polled(vec![
            member(av(), P::PRESENT_VALUE, None, None),
            member(missing, P::PRESENT_VALUE, None, None),
            member(av(), P::LOG_BUFFER, None, None),
        ]),
        vec![
            LogValue::RealValue(42.5),
            failed(ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT),
            failed(ErrorClass::PROPERTY, ErrorCode::UNKNOWN_PROPERTY),
        ]
    );
}

#[test]
fn a_member_naming_another_device_logs_a_failure_for_that_member() {
    // AV-1 exists here, but Device 200 is not this device.
    assert_eq!(
        polled(vec![
            member(av(), P::PRESENT_VALUE, None, Some(200)),
            member(av(), P::PRESENT_VALUE, None, Some(THIS_DEVICE)),
            member(av(), P::PRESENT_VALUE, None, None),
        ]),
        vec![
            failed(
                ErrorClass::PROPERTY,
                ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED
            ),
            LogValue::RealValue(42.5),
            LogValue::RealValue(42.5),
        ]
    );
}

#[test]
fn an_indexed_member_reads_its_element() {
    assert_eq!(
        polled(vec![
            member(ao(), P::PRIORITY_ARRAY, Some(8), None),
            member(ao(), P::PRIORITY_ARRAY, Some(17), None),
            member(ao(), P::PRESENT_VALUE, Some(1), None),
            member(ao(), P::PRIORITY_ARRAY, None, None),
        ]),
        vec![
            LogValue::RealValue(61.5),
            failed(ErrorClass::PROPERTY, ErrorCode::INVALID_ARRAY_INDEX),
            failed(ErrorClass::PROPERTY, ErrorCode::PROPERTY_IS_NOT_AN_ARRAY),
            // A whole array is no loggable datatype.
            LogValue::NullValue,
        ]
    );
}

#[test]
fn an_empty_member_logs_no_property_specified() {
    let wildcard = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 4_194_303).unwrap();
    assert_eq!(
        polled(vec![
            member(wildcard, P::PRESENT_VALUE, None, None),
            member(av(), P::PRESENT_VALUE, None, Some(4_194_303)),
            member(av(), P::PRESENT_VALUE, None, None),
        ]),
        vec![
            failed(ErrorClass::PROPERTY, ErrorCode::NO_PROPERTY_SPECIFIED),
            failed(ErrorClass::PROPERTY, ErrorCode::NO_PROPERTY_SPECIFIED),
            LogValue::RealValue(42.5),
        ]
    );
}

#[test]
fn polled_records_follow_the_buffer_size_and_stop_when_full() {
    let sample = LogData::Values(vec![LogValue::RealValue(42.5)]);
    for stop_when_full in [false, true] {
        let (mut db, time) = database();
        let mut log = multiple(1, 2, vec![member(av(), P::PRESENT_VALUE, None, None)]);
        log.write_property(
            P::STOP_WHEN_FULL,
            None,
            PropertyValue::Boolean(stop_when_full),
            None,
        )
        .unwrap();
        let oid = log.object_identifier();
        db.add(Box::new(log)).unwrap();
        for poll in 1..=3u32 {
            *time.lock().unwrap() = Duration::from_millis(u64::from(poll) * 10);
            db.poll_trend_logs();
        }
        let data: Vec<_> = records(&db, oid).into_iter().map(|r| r.log_data).collect();
        let enabled = db
            .get(&oid)
            .unwrap()
            .read_property(P::LOG_ENABLE, None)
            .unwrap();
        if stop_when_full {
            // The second sample would fill the buffer, so a LOG_DISABLED
            // record takes its place and later polls add nothing.
            assert_eq!(data, vec![sample.clone(), LogData::LogStatus(0b001)]);
            assert_eq!(count(&db, oid), 2);
            assert_eq!(enabled, PropertyValue::Boolean(false));
        } else {
            // The oldest sample makes way for the newest.
            assert_eq!(data, vec![sample.clone(), sample.clone()]);
            assert_eq!(count(&db, oid), 3);
            assert_eq!(enabled, PropertyValue::Boolean(true));
        }
    }
}

#[test]
fn only_polled_logs_with_an_interval_and_members_are_sampled() {
    let one = || vec![member(av(), P::PRESENT_VALUE, None, None)];
    let mut triggered = multiple(u32::MAX, 8, one());
    triggered.set_logging_type(2);
    let mut cov = multiple(u32::MAX, 8, one());
    cov.set_logging_type(1);
    for log in [
        triggered,
        cov,
        multiple(0, 8, one()),
        multiple(u32::MAX, 8, Vec::new()),
    ] {
        let (mut db, _) = database();
        let oid = log.object_identifier();
        db.add(Box::new(log)).unwrap();
        db.poll_trend_logs();
        assert_eq!(count(&db, oid), 0);
        assert!(!db.trend_poll.0.contains_key(&oid));
    }
}

#[test]
fn a_disabled_log_accepts_the_poll_without_a_record() {
    let (mut db, _) = database();
    let mut log = multiple(
        u32::MAX,
        8,
        vec![member(av(), P::PRESENT_VALUE, None, None)],
    );
    log.bind_clock_internal(Some(Arc::new(WallClock(Mutex::new(Some(frame()))))));
    log.write_property(P::LOG_ENABLE, None, PropertyValue::Boolean(false), None)
        .unwrap();
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    db.poll_trend_logs();
    assert_eq!(
        records(&db, oid)
            .into_iter()
            .map(|r| r.log_data)
            .collect::<Vec<_>>(),
        vec![LogData::LogStatus(0b001)]
    );
    assert!(db.trend_poll.0[&oid].last_success.is_some());
}
