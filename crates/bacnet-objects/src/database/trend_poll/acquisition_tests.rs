//! How the poller acquires for a Trend Log Multiple (#1235): once per
//! Trigger, at clock-aligned boundaries, and only inside the Start_Time /
//! Stop_Time window, whose changes each pass records. The monotonic clock and
//! the Device clock are both set by hand.

use super::multiple_tests::{ao, av, clocked_database, member, multiple, records};
use super::*;
use crate::trend::TrendLogMultipleObject;
use bacnet_types::bitstring::LogStatus;
use bacnet_types::enums::LoggingType;

/// The fixture's day at `hour`:`minute`:`second`.`hundredths`.
fn at(hour: u8, minute: u8, second: u8, hundredths: u8) -> ClockFrame {
    ClockFrame {
        local_time: Time {
            hour,
            minute,
            second,
            hundredths,
        },
        ..frame()
    }
}

fn set_clock(clock: &WallClock, now: Option<ClockFrame>) {
    *clock.0.lock().unwrap() = now;
}

fn set_time(time: &Mutex<Duration>, now: Duration) {
    *time.lock().unwrap() = now;
}

fn read(db: &ObjectDatabase, oid: ObjectIdentifier, property: P) -> PropertyValue {
    db.get(&oid).unwrap().read_property(property, None).unwrap()
}

fn write_trigger(db: &mut ObjectDatabase, oid: ObjectIdentifier) {
    write(db, oid, P::TRIGGER, PropertyValue::Boolean(true));
}

fn triggered(members: Vec<BACnetDeviceObjectPropertyReference>) -> TrendLogMultipleObject {
    let mut log = multiple(0, 8, members);
    log.set_logging_type(LoggingType::TRIGGERED).unwrap();
    log
}

fn data(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<LogData> {
    records(db, oid).into_iter().map(|r| r.log_data).collect()
}

fn times(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<Time> {
    records(db, oid).into_iter().map(|r| r.time).collect()
}

const DISABLED: LogData = LogData::LogStatus(LogStatus::LOG_DISABLED);
const ENABLED: LogData = LogData::LogStatus(LogStatus::empty());

fn sample() -> LogData {
    LogData::Values(vec![LogValue::RealValue(42.5)])
}

#[test]
fn each_trigger_acquires_one_record_and_reads_false_again() {
    let (mut db, time, _) = clocked_database();
    let log = triggered(vec![
        member(av(), P::PRESENT_VALUE, None, None),
        member(ao(), P::PRESENT_VALUE, None, None),
    ]);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    db.poll_trend_logs();
    assert!(records(&db, oid).is_empty());

    write_trigger(&mut db, oid);
    assert_eq!(read(&db, oid, P::TRIGGER), PropertyValue::Boolean(true));
    db.poll_trend_logs();
    assert_eq!(
        data(&db, oid),
        [LogData::Values(vec![
            LogValue::RealValue(42.5),
            LogValue::RealValue(61.5),
        ])]
    );
    assert_eq!(read(&db, oid, P::TRIGGER), PropertyValue::Boolean(false));
    set_time(&time, Duration::from_secs(60));
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 1);

    // The next Trigger is a fresh acquisition, without waiting.
    write_trigger(&mut db, oid);
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 2);
    assert!(!db.trend_poll.0.contains_key(&oid));
}

#[test]
fn a_trigger_waits_for_a_clock_and_stays_true_until_served() {
    let (mut db, time, clock) = clocked_database();
    let log = triggered(vec![member(av(), P::PRESENT_VALUE, None, None)]);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    set_clock(&clock, None);
    write_trigger(&mut db, oid);
    db.poll_trend_logs();
    set_time(&time, RECONCILE - Duration::from_millis(1));
    set_clock(&clock, Some(frame()));
    db.poll_trend_logs();
    assert!(records(&db, oid).is_empty());
    assert_eq!(read(&db, oid, P::TRIGGER), PropertyValue::Boolean(true));
    // The failed attempt is retried after the usual 100 ms.
    set_time(&time, RECONCILE);
    db.poll_trend_logs();
    assert_eq!(data(&db, oid), [sample()]);
    assert_eq!(read(&db, oid, P::TRIGGER), PropertyValue::Boolean(false));
}

#[test]
fn a_trigger_is_served_without_members_and_while_disabled() {
    // No members: a record of no values, so Trigger doesn't stay TRUE.
    let (mut db, _, _) = clocked_database();
    let log = triggered(Vec::new());
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    write_trigger(&mut db, oid);
    db.poll_trend_logs();
    assert_eq!(data(&db, oid), [LogData::Values(Vec::new())]);
    assert_eq!(read(&db, oid, P::TRIGGER), PropertyValue::Boolean(false));

    // Disabled: nothing logged, but the Trigger is still served.
    let (mut db, _, _) = clocked_database();
    let log = triggered(vec![member(av(), P::PRESENT_VALUE, None, None)]);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    write(&mut db, oid, P::LOG_ENABLE, PropertyValue::Boolean(false));
    write_trigger(&mut db, oid);
    db.poll_trend_logs();
    assert_eq!(data(&db, oid), [DISABLED]);
    assert_eq!(read(&db, oid, P::TRIGGER), PropertyValue::Boolean(false));
}

/// A POLLED log of AV-1 every `interval` hundredths, aligned, added to a
/// database whose Device clock reads [`frame`] (12:00:00.37).
fn aligned(
    interval: u32,
    offset: u32,
) -> (
    ObjectDatabase,
    Arc<Mutex<Duration>>,
    Arc<WallClock>,
    ObjectIdentifier,
) {
    let (mut db, time, clock) = clocked_database();
    let mut log = multiple(
        interval,
        8,
        vec![member(av(), P::PRESENT_VALUE, None, None)],
    );
    log.set_align_intervals(true);
    log.set_interval_offset(offset);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    (db, time, clock, oid)
}

#[test]
fn aligned_polls_wait_for_each_boundary_and_never_take_one_twice() {
    // One minute divides an hour: acquire on each minute.
    let (mut db, time, clock, oid) = aligned(6_000, 0);
    db.poll_trend_logs();
    assert!(records(&db, oid).is_empty());
    let first = Duration::from_millis(59_630);
    assert_eq!(db.trend_poll.0[&oid].aligned_due, Some(first));
    set_time(&time, first - Duration::from_nanos(1));
    db.poll_trend_logs();
    assert!(records(&db, oid).is_empty());

    set_time(&time, first);
    set_clock(&clock, Some(at(12, 1, 0, 0)));
    db.poll_trend_logs();
    assert_eq!(times(&db, oid), [at(12, 1, 0, 0).local_time]);
    let second = first + Duration::from_secs(60);
    assert_eq!(db.trend_poll.0[&oid].aligned_due, Some(second));

    // A wake a hundredth early serves 12:02:00 and next waits for 12:03:00.
    set_time(&time, second);
    set_clock(&clock, Some(at(12, 1, 59, 99)));
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 2);
    let third = second + Duration::from_millis(60_010);
    assert_eq!(db.trend_poll.0[&oid].aligned_due, Some(third));
    set_time(&time, second + Duration::from_millis(10));
    set_clock(&clock, Some(at(12, 2, 0, 0)));
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 2);

    // A wake late for 12:03:00 waits for 12:04:00, not a full interval more.
    set_time(&time, third + Duration::from_millis(30));
    set_clock(&clock, Some(at(12, 3, 0, 3)));
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 3);
    assert_eq!(
        db.trend_poll.0[&oid].aligned_due,
        Some(third + Duration::from_millis(30 + 59_970))
    );
}

#[test]
fn interval_offset_shifts_each_boundary_modulo_the_interval() {
    // 6150 modulo one minute: 1.50 s past each minute, 1.13 s away.
    let (mut db, time, clock, oid) = aligned(6_000, 6_150);
    db.poll_trend_logs();
    let due = Duration::from_millis(1_130);
    assert_eq!(db.trend_poll.0[&oid].aligned_due, Some(due));
    set_time(&time, due);
    set_clock(&clock, Some(at(12, 0, 1, 50)));
    db.poll_trend_logs();
    assert_eq!(times(&db, oid), [at(12, 0, 1, 50).local_time]);

    // Without a clock, the first boundary is planned on a later pass.
    let (mut db, time, clock, oid) = aligned(6_000, 0);
    set_clock(&clock, None);
    db.poll_trend_logs();
    assert_eq!(db.trend_poll.0[&oid].aligned_due, None);
    set_clock(&clock, Some(frame()));
    set_time(&time, RECONCILE);
    db.poll_trend_logs();
    assert_eq!(
        db.trend_poll.0[&oid].aligned_due,
        Some(RECONCILE + Duration::from_millis(59_630))
    );
}

#[test]
fn alignment_needs_an_interval_that_divides_a_day() {
    // 70 s divides neither a minute, an hour nor a day, and an offset
    // without Align_Intervals does nothing: both poll at once.
    let (mut db, _, _, oid) = aligned(7_000, 50);
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 1);
    let (mut db, _, _) = clocked_database();
    let mut log = multiple(6_000, 8, vec![member(av(), P::PRESENT_VALUE, None, None)]);
    log.set_interval_offset(50);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 1);
    // Two hours divide a day: the first boundary is midnight, 12 hours on.
    let (mut db, _, _, oid) = aligned(720_000, 0);
    db.poll_trend_logs();
    assert_eq!(
        db.trend_poll.0[&oid].aligned_due,
        Some(Duration::from_millis(7_199_630))
    );
}

#[test]
fn each_pass_records_the_window_opening_and_closing() {
    let (mut db, time, clock) = clocked_database();
    // Every second, from 12:00:01 until 12:00:02, set before the first look.
    let mut log = multiple(100, 8, vec![member(av(), P::PRESENT_VALUE, None, None)]);
    let start = at(12, 0, 1, 0);
    let stop = at(12, 0, 2, 0);
    log.set_start_time(start.local_date, start.local_time)
        .unwrap();
    log.set_stop_time(stop.local_date, stop.local_time).unwrap();
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    db.poll_trend_logs();
    assert!(records(&db, oid).is_empty());
    set_time(&time, Duration::from_secs(1));
    set_clock(&clock, Some(at(12, 0, 1, 37)));
    db.poll_trend_logs();
    assert_eq!(data(&db, oid), [ENABLED, sample()]);
    set_time(&time, Duration::from_secs(2));
    set_clock(&clock, Some(at(12, 0, 2, 37)));
    db.poll_trend_logs();
    assert_eq!(data(&db, oid), [ENABLED, sample(), DISABLED]);

    // A TRIGGERED log acquires nothing, yet the pass still records the
    // window opening for it.
    let (mut db, _, clock) = clocked_database();
    let log = triggered(vec![member(av(), P::PRESENT_VALUE, None, None)]);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    let opens = at(12, 30, 0, 0);
    write(
        &mut db,
        oid,
        P::START_TIME,
        PropertyValue::List(vec![
            PropertyValue::Date(opens.local_date),
            PropertyValue::Time(opens.local_time),
        ]),
    );
    assert_eq!(data(&db, oid), [DISABLED]);
    set_clock(&clock, Some(opens));
    db.poll_trend_logs();
    assert_eq!(data(&db, oid), [DISABLED, ENABLED]);
    assert_eq!(times(&db, oid)[1], opens.local_time);
}
