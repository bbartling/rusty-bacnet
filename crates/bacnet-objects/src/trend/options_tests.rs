//! Trend Log's acquisition rows (#1354): Logging_Type limited to POLLED and
//! TRIGGERED until COV acquisition exists (#1480), Log_Interval's mode rules
//! (Clause 12.25.9), Trigger and the clock-alignment rows. The window is in
//! `crate::log_window_tests`, shared with the Event Log.

use super::*;
use crate::clock::ClockFrame;
use bacnet_types::constructed::LogDatum;
use bacnet_types::primitives::{Date, Time};

fn read(log: &TrendLogObject, property: PropertyIdentifier) -> PropertyValue {
    log.read_property(property, None).unwrap()
}

fn write(
    log: &mut TrendLogObject,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Result<(), Error> {
    log.write_property(property, None, value, None)
}

fn assert_refused(result: Result<(), Error>, class: ErrorClass, code: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class: c, code: e })
            if c == class.to_raw() as u32 && e == code.to_raw() as u32),
        "expected {class:?} / {code:?}, got {result:?}"
    );
}

fn interval(log: &TrendLogObject) -> PropertyValue {
    read(log, PropertyIdentifier::LOG_INTERVAL)
}

fn record() -> BACnetLogRecord {
    BACnetLogRecord {
        date: Date {
            year: 126,
            month: 10,
            day: 4,
            day_of_week: 7,
        },
        time: Time {
            hour: 9,
            minute: 0,
            second: 0,
            hundredths: 0,
        },
        log_datum: LogDatum::RealValue(1.5),
        status_flags: None,
    }
}

#[test]
fn logging_type_takes_polled_or_triggered_and_refuses_cov_for_now() {
    let mut log = TrendLogObject::new(1, "TL-1", 8).unwrap();
    log.set_log_interval(500).unwrap();
    // Clause 12.25.26 allows COV, but this device has no COV acquisition
    // (#1480), so COV is refused rather than served unacted on, with the
    // error that clause gives for a value the object doesn't support; so is
    // a value outside BACnetLoggingType. Through the wire and the setter
    // alike.
    for raw in [LoggingType::COV.to_raw(), 3, 255] {
        assert_refused(
            write(
                &mut log,
                PropertyIdentifier::LOGGING_TYPE,
                PropertyValue::Enumerated(raw),
            ),
            ErrorClass::PROPERTY,
            ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
        );
        assert_refused(
            log.set_logging_type(LoggingType::from_raw(raw)),
            ErrorClass::PROPERTY,
            ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
        );
    }
    assert_refused(
        write(
            &mut log,
            PropertyIdentifier::LOGGING_TYPE,
            PropertyValue::Unsigned(2),
        ),
        ErrorClass::PROPERTY,
        ErrorCode::INVALID_DATA_TYPE,
    );
    assert_eq!(
        read(&log, PropertyIdentifier::LOGGING_TYPE),
        PropertyValue::Enumerated(0)
    );
    assert_eq!(interval(&log), PropertyValue::Unsigned(500));

    // TRIGGERED zeroes Log_Interval, which is then read-only.
    write(
        &mut log,
        PropertyIdentifier::LOGGING_TYPE,
        PropertyValue::Enumerated(2),
    )
    .unwrap();
    assert_eq!(interval(&log), PropertyValue::Unsigned(0));
    assert!(!log.is_writable_property(PropertyIdentifier::LOG_INTERVAL));
    for value in [PropertyValue::Unsigned(500), PropertyValue::Null] {
        assert_refused(
            write(&mut log, PropertyIdentifier::LOG_INTERVAL, value),
            ErrorClass::PROPERTY,
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
    assert_refused(
        log.set_log_interval(500),
        ErrorClass::PROPERTY,
        ErrorCode::WRITE_ACCESS_DENIED,
    );

    // POLLED with a zero interval takes the default; a nonzero one stays.
    log.set_logging_type(LoggingType::POLLED).unwrap();
    assert!(log.is_writable_property(PropertyIdentifier::LOG_INTERVAL));
    assert_eq!(
        interval(&log),
        PropertyValue::Unsigned(DEFAULT_LOG_INTERVAL.into())
    );
    log.set_log_interval(250).unwrap();
    log.set_logging_type(LoggingType::POLLED).unwrap();
    assert_eq!(interval(&log), PropertyValue::Unsigned(250));
}

#[test]
fn a_polled_interval_written_to_zero_is_a_refused_switch_to_cov() {
    let mut log = TrendLogObject::new(1, "TL-1", 8).unwrap();
    // A new log is POLLED at zero: writing zero again changes nothing and
    // asks for no switch.
    write(
        &mut log,
        PropertyIdentifier::LOG_INTERVAL,
        PropertyValue::Unsigned(0),
    )
    .unwrap();
    log.set_log_interval(0).unwrap();
    write(
        &mut log,
        PropertyIdentifier::LOG_INTERVAL,
        PropertyValue::Unsigned(300),
    )
    .unwrap();
    // From nonzero to zero is how Clause 12.25.9 switches a POLLED log to
    // COV, which is refused like a COV Logging_Type; the log stays as it was.
    assert_refused(
        write(
            &mut log,
            PropertyIdentifier::LOG_INTERVAL,
            PropertyValue::Unsigned(0),
        ),
        ErrorClass::PROPERTY,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    );
    assert_refused(
        log.set_log_interval(0),
        ErrorClass::PROPERTY,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    );
    assert_eq!(interval(&log), PropertyValue::Unsigned(300));
    assert_eq!(
        read(&log, PropertyIdentifier::LOGGING_TYPE),
        PropertyValue::Enumerated(0)
    );
    // Any other interval is taken, and so are the usual refusals.
    log.set_log_interval(1).unwrap();
    assert_eq!(interval(&log), PropertyValue::Unsigned(1));
    for (value, code) in [
        (
            PropertyValue::Unsigned(u64::from(u32::MAX) + 1),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
        (PropertyValue::Boolean(true), ErrorCode::INVALID_DATA_TYPE),
    ] {
        assert_refused(
            write(&mut log, PropertyIdentifier::LOG_INTERVAL, value),
            ErrorClass::PROPERTY,
            code,
        );
    }
    assert_eq!(interval(&log), PropertyValue::Unsigned(1));

    // A Trend Log Multiple has no such switch: zero leaves it idle.
    let mut multiple = TrendLogMultipleObject::new(1, "TLM-1", 8).unwrap();
    multiple.set_log_interval(300).unwrap();
    multiple.set_log_interval(0).unwrap();
    assert_eq!(
        multiple
            .read_property(PropertyIdentifier::LOG_INTERVAL, None)
            .unwrap(),
        PropertyValue::Unsigned(0)
    );
}

#[test]
fn trigger_asks_a_triggered_log_for_one_record() {
    let mut log = TrendLogObject::new(1, "TL-1", 8).unwrap();
    // Only a TRIGGERED log takes Trigger TRUE (Clause 12.25.29).
    assert_refused(
        write(
            &mut log,
            PropertyIdentifier::TRIGGER,
            PropertyValue::Boolean(true),
        ),
        ErrorClass::PROPERTY,
        ErrorCode::NOT_CONFIGURED_FOR_TRIGGERED_LOGGING,
    );
    assert_refused(
        log.trigger(),
        ErrorClass::PROPERTY,
        ErrorCode::NOT_CONFIGURED_FOR_TRIGGERED_LOGGING,
    );
    write(
        &mut log,
        PropertyIdentifier::TRIGGER,
        PropertyValue::Boolean(false),
    )
    .unwrap();

    log.set_logging_type(LoggingType::TRIGGERED).unwrap();
    write(
        &mut log,
        PropertyIdentifier::TRIGGER,
        PropertyValue::Boolean(true),
    )
    .unwrap();
    // FALSE doesn't take back an acquisition already asked for.
    write(
        &mut log,
        PropertyIdentifier::TRIGGER,
        PropertyValue::Boolean(false),
    )
    .unwrap();
    assert_eq!(
        read(&log, PropertyIdentifier::TRIGGER),
        PropertyValue::Boolean(true)
    );
    assert_refused(
        write(
            &mut log,
            PropertyIdentifier::TRIGGER,
            PropertyValue::Unsigned(1),
        ),
        ErrorClass::PROPERTY,
        ErrorCode::INVALID_DATA_TYPE,
    );
    // The record it asked for serves it.
    log.add_record(record()).unwrap();
    assert_eq!(
        read(&log, PropertyIdentifier::TRIGGER),
        PropertyValue::Boolean(false)
    );
    assert_eq!(log.records().len(), 1);

    // Leaving TRIGGERED drops a Trigger not yet served.
    log.trigger().unwrap();
    log.set_logging_type(LoggingType::POLLED).unwrap();
    assert_eq!(
        read(&log, PropertyIdentifier::TRIGGER),
        PropertyValue::Boolean(false)
    );
}

#[test]
fn a_record_the_log_ignores_still_serves_the_trigger() {
    struct Nine;
    impl ClockReader for Nine {
        fn read_clock(&self) -> Option<ClockFrame> {
            Some(ClockFrame {
                local_date: record().date,
                local_time: record().time,
                utc_offset: 0,
                daylight_savings_status: false,
            })
        }
    }
    let mut log = TrendLogObject::new(1, "TL-1", 8).unwrap();
    log.bind_clock_internal(Some(Arc::new(Nine)));
    log.set_logging_type(LoggingType::TRIGGERED).unwrap();
    let trigger = |log: &TrendLogObject| read(log, PropertyIdentifier::TRIGGER);

    // Enable FALSE: the record is ignored, but the acquisition was made.
    write(
        &mut log,
        PropertyIdentifier::LOG_ENABLE,
        PropertyValue::Boolean(false),
    )
    .unwrap();
    log.trigger().unwrap();
    log.add_record(record()).unwrap();
    assert_eq!(trigger(&log), PropertyValue::Boolean(false));
    assert!(log
        .records()
        .iter()
        .all(|r| matches!(r.log_datum, LogDatum::LogStatus(_))));

    // Outside the window, the same.
    write(
        &mut log,
        PropertyIdentifier::LOG_ENABLE,
        PropertyValue::Boolean(true),
    )
    .unwrap();
    let (date, time) = (record().date, record().time);
    log.set_start_time(date, Time { hour: 10, ..time }).unwrap();
    log.trigger().unwrap();
    log.add_record(record()).unwrap();
    assert_eq!(trigger(&log), PropertyValue::Boolean(false));
    assert!(log
        .records()
        .iter()
        .all(|r| matches!(r.log_datum, LogDatum::LogStatus(_))));
}

#[test]
fn alignment_rows_read_back_what_is_written() {
    let mut log = TrendLogObject::new(1, "TL-1", 8).unwrap();
    assert_eq!(
        read(&log, PropertyIdentifier::ALIGN_INTERVALS),
        PropertyValue::Boolean(false)
    );
    assert_eq!(
        read(&log, PropertyIdentifier::INTERVAL_OFFSET),
        PropertyValue::Unsigned(0)
    );
    write(
        &mut log,
        PropertyIdentifier::ALIGN_INTERVALS,
        PropertyValue::Boolean(true),
    )
    .unwrap();
    write(
        &mut log,
        PropertyIdentifier::INTERVAL_OFFSET,
        PropertyValue::Unsigned(31),
    )
    .unwrap();
    assert_eq!(
        read(&log, PropertyIdentifier::ALIGN_INTERVALS),
        PropertyValue::Boolean(true)
    );
    assert_eq!(
        read(&log, PropertyIdentifier::INTERVAL_OFFSET),
        PropertyValue::Unsigned(31)
    );
    log.set_align_intervals(false);
    log.set_interval_offset(7);
    assert_eq!(
        read(&log, PropertyIdentifier::ALIGN_INTERVALS),
        PropertyValue::Boolean(false)
    );
    assert_eq!(
        read(&log, PropertyIdentifier::INTERVAL_OFFSET),
        PropertyValue::Unsigned(7)
    );
    for (property, value) in [
        (
            PropertyIdentifier::ALIGN_INTERVALS,
            PropertyValue::Unsigned(1),
        ),
        (
            PropertyIdentifier::INTERVAL_OFFSET,
            PropertyValue::Boolean(true),
        ),
    ] {
        assert_refused(
            write(&mut log, property, value),
            ErrorClass::PROPERTY,
            ErrorCode::INVALID_DATA_TYPE,
        );
    }
}
