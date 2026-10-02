//! Timestamped COV-multiple history that one notification cannot carry goes
//! out in several (135-2020 §13.1, §13.18.1.1; #986).
//!
//! Each notification fits the smaller of the local maximum APDU and the one
//! the subscriber advertised in its SubscribeCOVPropertyMultiple request.
//! Older history goes first, and the last notification carries each
//! reference's latest change with the untimestamped values. Every envelope
//! names the last change its notification carries. Time is paused.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::analog::AnalogValueObject;
use bacnet_services::cov_multiple::COVNotificationMultipleRequest;
use bacnet_types::primitives::Time;
use tokio::time::Instant as TokioInstant;

const SMALL_APDU: u16 = 206;

/// One PV row: encoded value and Time_Of_Change.
type Row = (Vec<u8>, Option<Time>);

/// Encoded APDU length of `notification`: its service request plus the
/// unconfirmed (2 octets) or unsegmented confirmed (4 octets) header.
fn apdu_len(notification: &COVNotificationMultipleRequest, confirmed: bool) -> usize {
    let mut encoded = BytesMut::new();
    notification.encode(&mut encoded).unwrap();
    encoded.len() + if confirmed { 4 } else { 2 }
}

/// `notification` fits `limit`, and its envelope names the last PV change it
/// carries (PV changes here are one second apart, in capture order).
fn check(notification: &COVNotificationMultipleRequest, limit: u16, confirmed: bool) {
    let len = apdu_len(notification, confirmed);
    assert!(
        len <= usize::from(limit),
        "{len}-octet APDU exceeds {limit}"
    );
    let rows: Vec<_> = notification
        .list_of_cov_notifications
        .iter()
        .filter(|item| item.monitored_object_identifier == av1())
        .flat_map(|item| &item.list_of_values)
        .filter(|value| value.property_identifier == PV)
        .collect();
    let last = rows
        .last()
        .and_then(|value| value.time_of_change)
        .expect("a timestamped PV row");
    assert_eq!(
        envelope(notification),
        Some((at(0).local_date, last)),
        "the envelope names the last change carried"
    );
}

/// AV-1's PV rows of a notification that may also carry other objects.
fn av1_pv_rows(notification: &COVNotificationMultipleRequest) -> Vec<Row> {
    notification
        .list_of_cov_notifications
        .iter()
        .filter(|item| item.monitored_object_identifier == av1())
        .flat_map(|item| &item.list_of_values)
        .filter(|value| value.property_identifier == PV)
        .map(|value| (value.value.clone(), value.time_of_change))
        .collect()
}

/// Queue PV changes at seconds `first..first + count` behind
/// DISABLE_INITIATION, then re-enable and change once more, which reports
/// them all. Returns every change as its expected row, in capture order.
async fn hold_then_release(h: &Harness, first: u8, count: u8) -> Vec<Row> {
    h.server.comm_state.store(2, Ordering::Release);
    let mut expected = Vec::new();
    for second in first..=first + count {
        if second == first + count {
            h.server.comm_state.store(0, Ordering::Release);
        }
        h.set_clock(second);
        let value = f32::from(second);
        h.write_local(value).await;
        expected.push((real(value), Some(time(second))));
    }
    expected
}

/// Unconfirmed notifications up to the one carrying `expected`'s last change,
/// each checked against `limit`.
async fn take_unconfirmed(
    h: &Harness,
    expected: &[Row],
    limit: u16,
) -> Vec<COVNotificationMultipleRequest> {
    let mut taken = Vec::new();
    let mut conveyed = Vec::new();
    while conveyed.last() != expected.last() {
        let notification = h.notification().await;
        check(&notification, limit, false);
        conveyed.extend(av1_pv_rows(&notification));
        taken.push(notification);
    }
    assert_eq!(conveyed, expected, "every change once, oldest first");
    taken
}

#[tokio::test(start_paused = true)]
async fn unconfirmed_history_beyond_one_apdu_goes_out_in_several_notifications() {
    let mut h = Harness::start(ServerConfig {
        max_apdu_length: u32::from(SMALL_APDU),
        ..ServerConfig::default()
    })
    .await;
    h.subscribe(false).await;
    h.notification().await;
    let expected = hold_then_release(&h, 1, 15).await;
    let taken = take_unconfirmed(&h, &expected, SMALL_APDU).await;
    assert!(taken.len() >= 3, "{} notifications", taken.len());
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 0);
    // Each was retired when it was sent.
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn notifications_fit_the_maximum_apdu_the_subscriber_advertised() {
    let mut h = Harness::start(ServerConfig::default()).await;
    h.request_max_apdu = SMALL_APDU;
    h.subscribe(false).await;
    check(&h.notification().await, SMALL_APDU, false);
    let expected = hold_then_release(&h, 1, 15).await;
    let taken = take_unconfirmed(&h, &expected, SMALL_APDU).await;
    assert!(taken.len() >= 3, "{} notifications", taken.len());
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 0);
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

fn av2() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 2).unwrap()
}

#[tokio::test(start_paused = true)]
async fn untimestamped_values_and_latest_changes_go_in_the_last_notification() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(AnalogValueObject::new(2, "AV-2", 62).unwrap()))
            .unwrap();
    })
    .await;
    h.request_max_apdu = SMALL_APDU;
    h.subscribe_specs(
        false,
        vec![(av1(), vec![(PV, true)]), (av2(), vec![(PV, false)])],
    )
    .await;
    h.notification().await;
    // AV-1's changes queue; AV-2's untimestamped change then reports them.
    h.server.comm_state.store(2, Ordering::Release);
    let mut expected = Vec::new();
    for second in 1..=15u8 {
        h.set_clock(second);
        h.write_local(f32::from(second)).await;
        expected.push((real(f32::from(second)), Some(time(second))));
    }
    h.server.comm_state.store(0, Ordering::Release);
    h.set_clock(16);
    h.write_local_to(av2(), 7.0).await;
    let mut taken = Vec::new();
    let mut conveyed = Vec::new();
    while conveyed.last() != expected.last() {
        let notification = h.notification().await;
        check(&notification, SMALL_APDU, false);
        conveyed.extend(av1_pv_rows(&notification));
        taken.push(notification);
    }
    assert_eq!(conveyed, expected);
    assert!(taken.len() >= 2, "{} notifications", taken.len());
    let carries_av2 = |notification: &COVNotificationMultipleRequest| {
        notification
            .list_of_cov_notifications
            .iter()
            .any(|item| item.monitored_object_identifier == av2())
    };
    let (last, earlier) = taken.split_last().unwrap();
    assert!(earlier.iter().all(|n| !carries_av2(n)), "history goes first");
    let av2_pv: Vec<_> = last
        .list_of_cov_notifications
        .iter()
        .filter(|item| item.monitored_object_identifier == av2())
        .flat_map(|item| &item.list_of_values)
        .filter(|value| value.property_identifier == PV)
        .map(|value| (value.value.clone(), value.time_of_change))
        .collect();
    assert_eq!(av2_pv, vec![(real(7.0), None)]);
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 0);
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn confirmed_history_chunks_go_out_one_per_acknowledgment() {
    let mut h = Harness::start(ServerConfig {
        max_apdu_length: u32::from(SMALL_APDU),
        ..ServerConfig::default()
    })
    .await;
    h.subscribe(true).await;
    h.notification().await;
    h.ack().await;
    h.settle().await;
    let expected = hold_then_release(&h, 1, 15).await;
    let mut conveyed = Vec::new();
    let mut count = 0;
    loop {
        let notification = h.notification().await;
        check(&notification, SMALL_APDU, true);
        conveyed.extend(av1_pv_rows(&notification));
        count += 1;
        if conveyed.last() == expected.last() {
            break;
        }
        // The rest stays queued, uncounted, until this chunk's Ack.
        h.no_notification().await;
        assert_eq!(h.server.cov_counters().timed_changes_dropped, 0);
        h.ack().await;
    }
    h.ack().await;
    h.settle().await;
    assert!(count >= 3, "{count} notifications");
    assert_eq!(conveyed, expected, "every change once, oldest first");
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 0);
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

/// Hold-off after a failed confirmed report with a 10 ms retry timeout.
const HOLD_OFF: Duration = Duration::from_millis(10 * (DEFAULT_APDU_RETRIES as u64 + 1));

#[tokio::test(start_paused = true)]
async fn a_failed_confirmed_chunk_goes_out_again_before_the_rest() {
    let mut h = Harness::start(ServerConfig {
        max_apdu_length: u32::from(SMALL_APDU),
        cov_retry_timeout_ms: 10,
        ..ServerConfig::default()
    })
    .await;
    h.subscribe_with_delay(true, vec![(av1(), vec![(PV, true)])], 1)
        .await;
    h.notification().await;
    h.ack().await;
    h.settle().await;
    let expected = hold_then_release(&h, 1, 15).await;
    let first = h.notification().await;
    check(&first, SMALL_APDU, true);
    assert_ne!(av1_pv_rows(&first).last(), expected.last(), "a first chunk");
    // Never acknowledged: its retries run out and the context holds off; the
    // Max_Notification_Delay backstop then reports the context again.
    h.workers_idle().await;
    tokio::time::sleep(HOLD_OFF).await;
    let again = h.notification().await;
    assert_eq!(av1_pv_rows(&again), av1_pv_rows(&first));
    let mut conveyed = av1_pv_rows(&again);
    while conveyed.last() != expected.last() {
        h.ack().await;
        let notification = h.notification().await;
        check(&notification, SMALL_APDU, true);
        conveyed.extend(av1_pv_rows(&notification));
    }
    h.ack().await;
    assert_eq!(conveyed, expected);
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 0);
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn chunks_an_exhausted_budget_held_back_go_out_at_the_deadline() {
    let mut h = Harness::start(ServerConfig {
        cov_policy: crate::cov::CovPolicy {
            max_notifications_per_event: 1,
            ..crate::cov::CovPolicy::default()
        },
        ..ServerConfig::default()
    })
    .await;
    h.request_max_apdu = SMALL_APDU;
    h.subscribe_with_delay(false, vec![(av1(), vec![(PV, true)])], 2)
        .await;
    h.notification().await;
    let expected = hold_then_release(&h, 1, 15).await;
    let released = TokioInstant::now();
    let first = h.notification().await;
    check(&first, SMALL_APDU, false);
    // One notification per event: the rest waits for the backstop.
    h.no_notification().await;
    let mut conveyed = av1_pv_rows(&first);
    let mut count = 1;
    while conveyed.last() != expected.last() {
        let notification = h.notification().await;
        check(&notification, SMALL_APDU, false);
        conveyed.extend(av1_pv_rows(&notification));
        count += 1;
    }
    assert!(count >= 3, "{count} notifications");
    assert!(
        released.elapsed() >= Duration::from_secs(2),
        "later chunks waited for the deadline"
    );
    assert_eq!(conveyed, expected);
    assert_eq!(h.server.cov_counters().timed_changes_dropped, 0);
    h.server.stop().await.unwrap();
}
