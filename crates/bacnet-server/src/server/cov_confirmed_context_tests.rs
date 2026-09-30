//! One confirmed COV-multiple context has one outstanding report (#896).
//!
//! Every notification to a context carries all the timestamped changes queued
//! for it (Clauses 13.1, 13.16.3.1.2.3 and 13.17.1.1.5), so a change to one
//! reference waits while another reference's report is outstanding, and the next
//! notification batches everything held. The context here watches AV-1 and BV-1
//! Present_Value and the decoded wire is checked. Time is paused, so each wait
//! also lets the server finish the work it has ready.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::binary::BinaryValueObject;
use bacnet_services::cov_multiple::COVNotificationMultipleRequest;
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::Time;

const ACTIVE: u32 = 1;

fn bv1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::BINARY_VALUE, 1).unwrap()
}

fn enumerated(value: u32) -> Vec<u8> {
    let mut encoded = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(
        &mut encoded,
        &PropertyValue::Enumerated(value),
    )
    .unwrap();
    encoded.to_vec()
}

async fn start(cov_retry_timeout_ms: u64) -> Harness {
    Harness::start_with(
        ServerConfig {
            cov_retry_timeout_ms,
            ..ServerConfig::default()
        },
        |db| {
            db.add(Box::new(BinaryValueObject::new(1, "BV-1").unwrap()))
                .unwrap();
        },
    )
    .await
}

/// Subscribe the context, AV-1 timestamped or not, and acknowledge its initial
/// report.
async fn subscribe(h: &mut Harness, timestamped: bool) {
    h.subscribe_specs(
        true,
        vec![(av1(), vec![(PV, timestamped)]), (bv1(), vec![(PV, false)])],
    )
    .await;
    h.notification().await;
    h.ack().await;
    h.settle().await;
}

/// `(value, time)` Present_Value rows of one object in a notification.
fn pv(
    notification: &COVNotificationMultipleRequest,
    object: ObjectIdentifier,
) -> Vec<(Vec<u8>, Option<Time>)> {
    notification
        .list_of_cov_notifications
        .iter()
        .filter(|item| item.monitored_object_identifier == object)
        .flat_map(|item| &item.list_of_values)
        .filter(|value| value.property_identifier == PV)
        .map(|value| (value.value.clone(), value.time_of_change))
        .collect()
}

async fn write_bv1(h: &Harness, value: u32) {
    h.server
        .write_local(
            &bv1(),
            PV,
            None,
            PropertyValue::Enumerated(value),
            Some(8),
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_context_holds_every_change_until_the_ack_then_batches_them() {
    let mut h = start(3000).await;
    subscribe(&mut h, true).await;
    h.set_clock(10);
    h.write_local(1.0).await;
    let first = h.notification().await;
    assert_eq!(pv(&first, av1()), vec![(real(1.0), Some(time(10)))]);
    assert!(pv(&first, bv1()).is_empty());
    // A timestamped change of the same reference and a change of its
    // untimestamped sibling both wait for that report.
    h.set_clock(11);
    h.write_local(2.0).await;
    write_bv1(&h, ACTIVE).await;
    h.no_notification().await;
    h.ack().await;
    let batched = h.notification().await;
    assert_eq!(pv(&batched, av1()), vec![(real(2.0), Some(time(11)))]);
    assert_eq!(pv(&batched, bv1()), vec![(enumerated(ACTIVE), None)]);
    h.ack().await;
    h.settle().await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_failed_context_report_returns_its_history_to_the_next_report() {
    let mut h = start(10).await;
    subscribe(&mut h, true).await;
    h.set_clock(10);
    h.write_local(1.0).await;
    assert_eq!(
        pv(&h.notification().await, av1()),
        vec![(real(1.0), Some(time(10)))]
    );
    h.set_clock(11);
    h.write_local(2.0).await;
    write_bv1(&h, ACTIVE).await;
    // No answer to any retry, then the context holds off: a fanout inside the
    // hold-off sends nothing.
    h.workers_idle().await;
    write_bv1(&h, ACTIVE).await;
    h.no_notification().await;
    // The next fanout batches the unacknowledged history, the change held
    // meanwhile and the sibling.
    write_bv1(&h, ACTIVE).await;
    let batched = h.notification().await;
    assert_eq!(
        pv(&batched, av1()),
        vec![(real(1.0), Some(time(10))), (real(2.0), Some(time(11)))]
    );
    assert_eq!(pv(&batched, bv1()), vec![(enumerated(ACTIVE), None)]);
    h.ack().await;
    h.settle().await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_resubscription_during_a_flight_reports_without_waiting_and_keeps_the_rest() {
    let mut h = start(3000).await;
    subscribe(&mut h, false).await;
    write_bv1(&h, ACTIVE).await;
    let first = h.notification().await;
    assert_eq!(pv(&first, bv1()), vec![(enumerated(ACTIVE), None)]);
    let old = h.take_confirmed();
    h.write_local(1.0).await;
    h.no_notification().await;
    // Re-subscribing to AV-1 alone does not wait for the old report. Either the
    // initial report or the fence follow-up goes first; both carry AV-1.
    h.subscribe_specs(true, vec![(av1(), vec![(PV, false)])])
        .await;
    let next = h.notification().await;
    assert_eq!(pv(&next, av1()), vec![(real(1.0), None)]);
    let mut kept = pv(&next, bv1());
    let new = h.take_confirmed();
    // The superseded report stopped; its Ack finds nothing to complete.
    h.ack_request(old).await;
    h.settle().await;
    h.no_notification().await;
    // BV-1, which the re-subscription kept, is reported by now or right after.
    h.ack_request(new).await;
    if kept.is_empty() {
        let follow_up = h.notification().await;
        assert!(pv(&follow_up, av1()).is_empty(), "AV-1 is acknowledged");
        kept = pv(&follow_up, bv1());
        h.ack().await;
    }
    assert_eq!(kept, vec![(enumerated(ACTIVE), None)]);
    h.settle().await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_ack_follows_up_the_context_when_its_carried_references_are_gone() {
    let mut h = start(3000).await;
    subscribe(&mut h, false).await;
    h.write_local(1.0).await;
    assert_eq!(pv(&h.notification().await, av1()), vec![(real(1.0), None)]);
    write_bv1(&h, ACTIVE).await;
    h.no_notification().await;
    // AV-1's reference goes while its report is outstanding, as when AV-1 is
    // deleted; BV-1's change is still held.
    h.server.cov_table.write().await.remove_for_object(av1());
    h.ack().await;
    let follow_up = h.notification().await;
    assert_eq!(pv(&follow_up, bv1()), vec![(enumerated(ACTIVE), None)]);
    assert!(pv(&follow_up, av1()).is_empty());
    h.ack().await;
    h.settle().await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn after_a_hold_off_one_fanout_reports_the_whole_context() {
    let mut h = start(10).await;
    subscribe(&mut h, false).await;
    write_bv1(&h, ACTIVE).await;
    assert_eq!(
        pv(&h.notification().await, bv1()),
        vec![(enumerated(ACTIVE), None)]
    );
    // No answer to any retry; wait out the hold-off, one full retry cycle.
    h.workers_idle().await;
    tokio::time::sleep(Duration::from_millis(
        10 * (u64::from(DEFAULT_APDU_RETRIES) + 1),
    ))
    .await;
    // A fanout on AV-1 alone brings BV-1's unacknowledged change along.
    h.write_local(1.0).await;
    let report = h.notification().await;
    assert_eq!(pv(&report, av1()), vec![(real(1.0), None)]);
    assert_eq!(pv(&report, bv1()), vec![(enumerated(ACTIVE), None)]);
    h.ack().await;
    h.settle().await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
