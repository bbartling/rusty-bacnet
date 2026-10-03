//! Clock-aligned polling of a Trend Log Multiple (#1235): boundaries on the
//! Device clock, Interval_Offset, and the plan following the Device clock
//! when it is changed. The rig moves the monotonic clock and the Device clock
//! by hand, together unless a test changes the Device clock on its own.

use super::acquisition_tests::{set_clock, set_time};
use super::multiple_tests::{av, clocked_database, member, multiple, records};
use super::*;
use bacnet_types::calendar::SpecificDate;

const MINUTE: i64 = 6_000;
const HOUR: i64 = 360_000;
const DAY: i64 = 24 * HOUR;

/// The Device clock `local` hundredths after midnight starting 2024-02-29,
/// the fixture's day, running on into the next days.
fn device_clock(local: i64) -> ClockFrame {
    let mut day = SpecificDate::new(2024, 2, 29).unwrap();
    for _ in 0..local.div_euclid(DAY) {
        let (year, month, next) = (day.year(), day.month(), day.day() + 1);
        day = SpecificDate::new(year, month, next)
            .or_else(|| SpecificDate::new(year, month + 1, 1))
            .unwrap_or_else(|| SpecificDate::new(year + 1, 1, 1).unwrap());
    }
    let tod = local.rem_euclid(DAY);
    ClockFrame {
        local_date: day.to_date(),
        local_time: Time {
            hour: (tod / HOUR) as u8,
            minute: (tod / MINUTE % 60) as u8,
            second: (tod / 100 % 60) as u8,
            hundredths: (tod % 100) as u8,
        },
        ..frame()
    }
}

/// A database holding one aligned POLLED log of AV-1, and both clocks.
struct Rig {
    db: ObjectDatabase,
    oid: ObjectIdentifier,
    time: Arc<Mutex<Duration>>,
    clock: Arc<WallClock>,
    monotonic: Duration,
    /// The Device clock, as for [`device_clock`].
    local: i64,
}

impl Rig {
    /// Log every `interval` hundredths, `offset` past each boundary, with the
    /// Device clock at `local`. Nothing is polled yet.
    fn new(interval: u32, offset: u32, local: i64) -> Self {
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
        let mut rig = Self {
            db,
            oid,
            time,
            clock,
            monotonic: Duration::ZERO,
            local,
        };
        rig.set_clocks();
        rig
    }

    fn set_clocks(&mut self) {
        set_time(&self.time, self.monotonic);
        set_clock(&self.clock, Some(device_clock(self.local)));
    }

    /// Let `hundredths` pass on both clocks, then poll.
    fn pass(&mut self, hundredths: i64) {
        self.monotonic += Duration::from_millis(hundredths as u64 * 10);
        self.local += hundredths;
        self.set_clocks();
        self.db.poll_trend_logs();
    }

    /// Change the Device clock to `local` while `elapsed` hundredths pass on
    /// the monotonic clock, as setting the clock does, then poll.
    fn set_device_clock(&mut self, local: i64, elapsed: i64) {
        self.monotonic += Duration::from_millis(elapsed as u64 * 10);
        self.local = local;
        self.set_clocks();
        self.db.poll_trend_logs();
    }

    /// The wait the schedule asks for now, before the 100 ms cap.
    fn wait(&self) -> Duration {
        self.db.trend_poll.0[&self.oid].remaining(self.monotonic)
    }

    /// Sleep as the server would until the log's next wake, then poll.
    fn wake(&mut self) {
        let wait = self.wait();
        self.pass((wait.as_millis() / 10) as i64);
    }

    /// When each record was taken, as Device-clock hundredths.
    fn taken(&self) -> Vec<i64> {
        records(&self.db, self.oid)
            .iter()
            .map(|record| {
                let day = SpecificDate::from_date(&record.date)
                    .unwrap()
                    .days_since_1970()
                    - SpecificDate::new(2024, 2, 29).unwrap().days_since_1970();
                let t = record.time;
                day * DAY
                    + i64::from(t.hour) * HOUR
                    + i64::from(t.minute) * MINUTE
                    + i64::from(t.second) * 100
                    + i64::from(t.hundredths)
            })
            .collect()
    }
}

#[test]
fn aligned_polls_wait_for_each_boundary_and_never_take_one_twice() {
    // One minute divides an hour: acquire on each minute, first at 12:01.
    let mut rig = Rig::new(6_000, 0, 12 * HOUR + 37);
    rig.pass(0);
    assert!(rig.taken().is_empty());
    assert_eq!(rig.wait(), Duration::from_millis(59_630));
    rig.pass(5_962);
    assert!(rig.taken().is_empty());
    rig.wake();
    assert_eq!(rig.taken(), [12 * HOUR + MINUTE]);
    assert_eq!(rig.wait(), Duration::from_secs(60));

    // The Device clock a hundredth slow at the wake: nothing until it reaches
    // 12:02, then that boundary once.
    rig.set_device_clock(12 * HOUR + 2 * MINUTE - 1, 6_000);
    assert_eq!(rig.taken().len(), 1);
    assert_eq!(rig.wait(), Duration::from_millis(10));
    rig.wake();
    // A further pass a hundredth on takes nothing more.
    rig.pass(1);
    assert_eq!(rig.taken(), [12 * HOUR + MINUTE, 12 * HOUR + 2 * MINUTE]);

    // A wake late for 12:03 (now 12:02:00.01) takes it then, and waits for
    // 12:04.
    rig.pass(MINUTE + 2);
    assert_eq!(rig.taken()[2], 12 * HOUR + 3 * MINUTE + 3);
    assert_eq!(rig.wait(), Duration::from_millis(59_970));
}

#[test]
fn interval_offset_shifts_each_boundary_modulo_the_interval() {
    // 6150 modulo one minute: 1.50 s past each minute, 1.13 s away.
    let mut rig = Rig::new(6_000, 6_150, 12 * HOUR + 37);
    rig.pass(0);
    assert_eq!(rig.wait(), Duration::from_millis(1_130));
    rig.wake();
    assert_eq!(rig.taken(), [12 * HOUR + 150]);

    // Without a clock there is nothing to plan by; a later pass plans it.
    let mut rig = Rig::new(6_000, 0, 12 * HOUR + 37);
    set_clock(&rig.clock, None);
    rig.db.poll_trend_logs();
    assert_eq!(rig.wait(), RECONCILE);
    rig.pass(10);
    assert_eq!(rig.wait(), Duration::from_millis(59_530));
}

#[test]
fn alignment_needs_an_interval_that_divides_a_day() {
    // 70 s divides neither a minute, an hour nor a day: polled at once.
    let mut rig = Rig::new(7_000, 50, 12 * HOUR + 37);
    rig.pass(0);
    assert_eq!(rig.taken().len(), 1);
    // An offset without Align_Intervals does nothing either.
    let (mut db, _, _) = clocked_database();
    let mut log = multiple(6_000, 8, vec![member(av(), P::PRESENT_VALUE, None, None)]);
    log.set_interval_offset(50);
    let oid = log.object_identifier();
    db.add(Box::new(log)).unwrap();
    db.poll_trend_logs();
    assert_eq!(records(&db, oid).len(), 1);
    // Two hours divide a day: from 12:00:00.37 the next boundary is 14:00.
    let mut rig = Rig::new(720_000, 0, 12 * HOUR + 37);
    rig.pass(0);
    assert_eq!(rig.wait(), Duration::from_millis(7_199_630));
}

#[test]
fn a_clock_set_forward_moves_the_plan_without_an_off_boundary_record() {
    let mut rig = Rig::new(360_000, 0, 13 * HOUR - 10 * MINUTE);
    rig.pass(0);
    rig.wake();
    assert_eq!(rig.taken(), [13 * HOUR]);
    // Five minutes on, the clock is set forward 40 minutes: 13:45.
    rig.pass(5 * MINUTE);
    rig.set_device_clock(13 * HOUR + 45 * MINUTE, 0);
    assert_eq!(rig.wait(), Duration::from_secs(15 * 60));
    rig.wake();
    rig.wake();
    assert_eq!(rig.taken(), [13 * HOUR, 14 * HOUR, 15 * HOUR]);

    // A jump past a boundary skips it rather than logging it off the grid.
    rig.pass(50 * MINUTE);
    rig.set_device_clock(16 * HOUR + 30 * MINUTE, 0);
    rig.wake();
    assert_eq!(rig.taken()[3..], [17 * HOUR]);
}

#[test]
fn a_clock_set_back_logs_each_boundary_as_the_clock_reaches_it() {
    // Two hours across a daylight-saving fall-back: 00:00 is logged, then at
    // 02:00 the clock goes back to 01:00, and 02:00 is next logged when the
    // clock reaches it again, never at 01:00.
    let mut rig = Rig::new(720_000, 0, -10 * MINUTE);
    rig.pass(0);
    rig.wake();
    assert_eq!(rig.taken(), [0]);
    rig.pass(2 * HOUR - MINUTE);
    rig.set_device_clock(HOUR, MINUTE);
    assert_eq!(rig.taken(), [0]);
    assert_eq!(rig.wait(), Duration::from_secs(3_600));
    rig.wake();
    assert_eq!(rig.taken(), [0, 2 * HOUR]);

    // Set back past a boundary already logged: logged again when reached.
    rig.pass(10 * MINUTE);
    rig.set_device_clock(HOUR + 50 * MINUTE, 0);
    rig.wake();
    assert_eq!(rig.taken(), [0, 2 * HOUR, 2 * HOUR]);
}

#[test]
fn boundaries_run_on_across_midnight() {
    let mut rig = Rig::new(6_000, 0, 24 * HOUR - 90 * 100);
    rig.pass(0);
    for _ in 0..3 {
        rig.wake();
    }
    assert_eq!(
        rig.taken(),
        [24 * HOUR - MINUTE, 24 * HOUR, 24 * HOUR + MINUTE]
    );
    let dates: Vec<_> = records(&rig.db, rig.oid).iter().map(|r| r.date).collect();
    assert_eq!(dates[0], frame().local_date);
    assert_eq!(
        dates[1..],
        [SpecificDate::new(2024, 3, 1).unwrap().to_date(); 2]
    );
}

#[test]
fn a_log_interval_change_mid_wait_plans_from_the_new_interval() {
    let mut rig = Rig::new(360_000, 0, 13 * HOUR - 10 * MINUTE);
    rig.pass(0);
    rig.wake();
    assert_eq!(rig.taken(), [13 * HOUR]);
    rig.pass(10 * MINUTE);
    write(
        &mut rig.db,
        rig.oid,
        P::LOG_INTERVAL,
        PropertyValue::Unsigned(90_000),
    );
    rig.pass(0);
    assert_eq!(rig.wait(), Duration::from_secs(5 * 60));
    rig.wake();
    rig.wake();
    assert_eq!(
        rig.taken(),
        [13 * HOUR, 13 * HOUR + 15 * MINUTE, 13 * HOUR + 30 * MINUTE]
    );
}
