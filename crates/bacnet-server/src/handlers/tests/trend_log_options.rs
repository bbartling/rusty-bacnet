//! A Trend Log's Logging_Type, Log_Interval and Trigger (#1354), and the
//! Start_Time / Stop_Time window of a Trend Log and an Event Log (#1353),
//! over WriteProperty and ReadProperty.

use super::*;
use bacnet_encoding::constructed::{decode_event_log_record, decode_log_record};
use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::event_log::EventLogObject;
use bacnet_objects::trend::TrendLogObject;
use bacnet_types::bitstring::LogStatus;
use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, EventLogDatum, LogDatum};
use std::sync::Arc;

use PropertyIdentifier as P;

fn tl1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::TREND_LOG, 1).unwrap()
}

fn el1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::EVENT_LOG, 1).unwrap()
}

/// AV-1 at 21.5, a Trend Log of its Present_Value and an Event Log, with
/// both clocks bound.
fn database() -> ObjectDatabase {
    let mut db = crate::server::clocked_test_database();
    let mut av = AnalogValueObject::new(1, "AV-1", 95).unwrap();
    av.set_relinquish_default(21.5).unwrap();
    db.add(Box::new(av)).unwrap();
    let mut tl = TrendLogObject::new(1, "TL-1", 8).unwrap();
    tl.set_log_device_object_property(Some(BACnetDeviceObjectPropertyReference::new_local(
        ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap(),
        P::PRESENT_VALUE.to_raw(),
    )))
    .unwrap();
    db.add(Box::new(tl)).unwrap();
    db.add(Box::new(EventLogObject::new(1, "EL-1", 8).unwrap()))
        .unwrap();
    db.set_monotonic_clock_internal(Some(Arc::new(|| std::time::Duration::ZERO)));
    db
}

/// A WriteProperty of `value`, application-tagged bytes, to `oid`.
fn wp(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    property: P,
    value: &[u8],
) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: None,
        property_value: value.to_vec(),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    sourced_wp(db, &request).map(|_| ())
}

/// The value bytes a ReadProperty of `oid`'s `property` returns.
fn rp(db: &ObjectDatabase, oid: ObjectIdentifier, property: P) -> Vec<u8> {
    let mut request = BytesMut::new();
    ReadPropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: None,
    }
    .encode(&mut request);
    let mut ack = BytesMut::new();
    handle_read_property(db, &request, &mut ack).unwrap();
    ReadPropertyACK::decode(&ack).unwrap().property_value
}

fn assert_refused(result: Result<(), Error>, class: ErrorClass, code: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class: c, code: e })
            if c == class.to_raw() as u32 && e == code.to_raw() as u32),
        "expected {class:?} / {code:?}, got {result:?}"
    );
}

/// Each record of `oid` as ReadRange serves it: its status, or `None` for
/// an ordinary record.
fn statuses(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<Option<LogStatus>> {
    let records = db.get(&oid).unwrap().log_buffer_internal().unwrap();
    (0..records.record_count())
        .map(|index| {
            let mut bytes = BytesMut::new();
            records.encode_record(index, &mut bytes);
            if oid.object_type() == ObjectType::TREND_LOG {
                match decode_log_record(&bytes, 0).unwrap().0.log_datum {
                    LogDatum::LogStatus(status) => Some(status),
                    _ => None,
                }
            } else {
                match decode_event_log_record(&bytes, 0).unwrap().0.log_datum {
                    EventLogDatum::LogStatus(status) => Some(status),
                    _ => None,
                }
            }
        })
        .collect()
}

const POLLED: [u8; 2] = [0x91, 0x00];
const COV: [u8; 2] = [0x91, 0x01];
const TRIGGERED: [u8; 2] = [0x91, 0x02];
const TRUE: [u8; 1] = [0x11];
const FALSE: [u8; 1] = [0x10];

#[test]
fn trend_log_logging_type_refuses_cov_and_steers_log_interval() {
    let mut db = database();
    wp(&mut db, tl1(), P::LOG_INTERVAL, &[0x21, 0x64]).unwrap();
    // No COV acquisition yet (#1480): COV, a value outside the enumeration,
    // and the Clause 12.25.9 route into COV all get the Clause 12.25.26
    // answer.
    for value in [COV, [0x91, 0x03]] {
        assert_refused(
            wp(&mut db, tl1(), P::LOGGING_TYPE, &value),
            ErrorClass::PROPERTY,
            ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
        );
    }
    assert_refused(
        wp(&mut db, tl1(), P::LOG_INTERVAL, &[0x21, 0x00]),
        ErrorClass::PROPERTY,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    );
    assert_eq!(rp(&db, tl1(), P::LOGGING_TYPE), POLLED);
    assert_eq!(rp(&db, tl1(), P::LOG_INTERVAL), [0x21, 0x64]);

    // TRIGGERED zeroes Log_Interval and makes it read-only.
    wp(&mut db, tl1(), P::LOGGING_TYPE, &TRIGGERED).unwrap();
    assert_eq!(rp(&db, tl1(), P::LOG_INTERVAL), [0x21, 0x00]);
    assert_refused(
        wp(&mut db, tl1(), P::LOG_INTERVAL, &[0x21, 0x64]),
        ErrorClass::PROPERTY,
        ErrorCode::WRITE_ACCESS_DENIED,
    );
    // A Trigger written over the wire is served by the next poll.
    db.poll_trend_logs();
    assert!(statuses(&db, tl1()).is_empty());
    wp(&mut db, tl1(), P::TRIGGER, &TRUE).unwrap();
    assert_eq!(rp(&db, tl1(), P::TRIGGER), TRUE);
    db.poll_trend_logs();
    assert_eq!(statuses(&db, tl1()), [None]);
    assert_eq!(rp(&db, tl1(), P::TRIGGER), FALSE);
}

#[test]
fn trend_log_and_event_log_windows_take_a_date_and_time() {
    let mut db = database();
    for oid in [tl1(), el1()] {
        // 2150-01-01 (a Thursday) at 08:30: long after this test runs, so
        // the window shuts now and says so.
        let start = [
            0xA4, 250, 1, 1, 4, // Date
            0xB4, 8, 30, 0, 0, // Time
        ];
        wp(&mut db, oid, P::START_TIME, &start).unwrap();
        assert_eq!(rp(&db, oid, P::START_TIME), start);
        assert_eq!(statuses(&db, oid), [Some(LogStatus::LOG_DISABLED)]);
        let unspecified = [0xA4, 0xFF, 0xFF, 0xFF, 0xFF, 0xB4, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(rp(&db, oid, P::STOP_TIME), unspecified);
        // A date with an unspecified year names no moment.
        let partly = [0xA4, 0xFF, 1, 1, 4, 0xB4, 8, 30, 0, 0];
        assert_refused(
            wp(&mut db, oid, P::STOP_TIME, &partly),
            ErrorClass::PROPERTY,
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_refused(
            wp(&mut db, oid, P::STOP_TIME, &start[..5]),
            ErrorClass::PROPERTY,
            ErrorCode::INVALID_DATA_TYPE,
        );
        // Back to unspecified: the window opens again.
        wp(&mut db, oid, P::START_TIME, &unspecified).unwrap();
        assert_eq!(
            statuses(&db, oid),
            [Some(LogStatus::LOG_DISABLED), Some(LogStatus::empty())]
        );
    }
}
