//! Max_Notification_Delay bounds how long timestamped changes stay queued
//! (135-2020 §13.1, §13.16.1.1.4; #856, part 2).
//!
//! Changes are reported as soon as they happen. These tests cover changes
//! that are still queued afterwards, because a send failed, a confirmed report
//! went unanswered or DISABLE_INITIATION held them, and nothing else changes:
//! they go out once the delay, measured from the earliest of them, has passed.
//! Time is paused, so Tokio jumps to each deadline while the test waits.
use super::cov_wire_test_support::*;
use super::*;
use tokio::time::Instant as TokioInstant;

const DELAY: u32 = 10;

/// Wait until just before `DELAY` seconds after `since`; nothing goes out yet.
async fn nothing_before_the_deadline(h: &Harness, since: TokioInstant) {
    tokio::time::sleep_until(
        since + Duration::from_secs(u64::from(DELAY)) - Duration::from_millis(100),
    )
    .await;
    h.no_notification().await;
}

/// The next notification, and that it went out at the deadline.
async fn notification_at_the_deadline(
    h: &Harness,
    since: TokioInstant,
) -> bacnet_services::cov_multiple::COVNotificationMultipleRequest {
    let report = h.notification().await;
    let elapsed = since.elapsed();
    let delay = Duration::from_secs(u64::from(DELAY));
    assert!(
        elapsed >= delay && elapsed < delay + Duration::from_secs(1),
        "sent {elapsed:?} after the earliest change, not at the {delay:?} deadline"
    );
    report
}

#[tokio::test(start_paused = true)]
async fn failed_sends_are_retried_at_the_delay_from_the_earliest_change() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe_with_delay(false, vec![(av1(), vec![(PV, true)])], DELAY)
        .await;
    h.notification().await;
    h.fail_notifications.store(true, Ordering::Release);
    h.set_clock(21);
    let earliest = TokioInstant::now();
    h.write_local(5.0).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    h.set_clock(25);
    h.write_local(6.0).await;
    h.fail_notifications.store(false, Ordering::Release);
    nothing_before_the_deadline(&h, earliest).await;
    let report = notification_at_the_deadline(&h, earliest).await;
    assert_eq!(
        pv_rows(&report),
        vec![(real(5.0), Some(time(21))), (real(6.0), Some(time(25)))]
    );
    // Delivered: nothing is left for a later deadline.
    tokio::time::sleep(Duration::from_secs(u64::from(DELAY) * 3)).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn changes_held_by_disable_initiation_go_out_at_the_deadline() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe_with_delay(false, vec![(av1(), vec![(PV, true)])], DELAY)
        .await;
    h.notification().await;
    h.server.comm_state.store(2, Ordering::Release);
    h.set_clock(11);
    let earliest = TokioInstant::now();
    h.write_local(10.0).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    h.server.comm_state.store(0, Ordering::Release);
    nothing_before_the_deadline(&h, earliest).await;
    let report = notification_at_the_deadline(&h, earliest).await;
    assert_eq!(pv_rows(&report), vec![(real(10.0), Some(time(11)))]);
    h.server.stop().await.unwrap();
}

/// Hold-off after a failed confirmed report with a 10 ms retry timeout.
const HOLD_OFF: Duration = Duration::from_millis(10 * (DEFAULT_APDU_RETRIES as u64 + 1));

#[tokio::test(start_paused = true)]
async fn an_unacknowledged_confirmed_report_is_resent_at_the_deadline() {
    let mut h = Harness::start(ServerConfig {
        cov_retry_timeout_ms: 10,
        ..ServerConfig::default()
    })
    .await;
    h.subscribe_with_delay(true, vec![(av1(), vec![(PV, true)])], DELAY)
        .await;
    h.notification().await;
    h.ack().await;
    h.settle().await;
    h.set_clock(45);
    let earliest = TokioInstant::now();
    h.write_local(5.0).await;
    h.notification().await;
    // Never acknowledged: the retries run out and the context holds off.
    h.workers_idle().await;
    tokio::time::sleep(HOLD_OFF).await;
    nothing_before_the_deadline(&h, earliest).await;
    let report = notification_at_the_deadline(&h, earliest).await;
    assert_eq!(pv_rows(&report), vec![(real(5.0), Some(time(45)))]);
    h.ack().await;
    h.settle().await;
    tokio::time::sleep(Duration::from_secs(u64::from(DELAY) * 3)).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_delivered_change_owes_no_deadline_notification() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.subscribe_with_delay(false, vec![(av1(), vec![(PV, true)])], DELAY)
        .await;
    h.notification().await;
    h.set_clock(30);
    h.write_local(3.0).await;
    assert_eq!(
        pv_rows(&h.notification().await),
        vec![(real(3.0), Some(time(30)))]
    );
    tokio::time::sleep(Duration::from_secs(u64::from(DELAY) * 3)).await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
