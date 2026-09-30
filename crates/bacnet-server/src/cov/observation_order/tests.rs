use super::*;
use crate::cov::{CovNotificationKind, CovSample, CovSubscription};
use bacnet_types::{
    enums::{ObjectType, PropertyIdentifier},
    primitives::{ObjectIdentifier, PropertyValue},
    MacAddr,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
fn proposal(kind: CovNotificationKind, confirmed: bool) -> CovSubscription {
    CovSubscription {
        subscriber_mac: MacAddr::from_slice(&[1]),
        subscriber_network: None,
        subscriber_process_identifier: 1,
        monitored_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap(),
        issue_confirmed_notifications: confirmed,
        expires_at: Some(Instant::now() + Duration::from_secs(60)),
        last_notified_observation: None,
        monitored_property: Some(PropertyIdentifier::PRESENT_VALUE),
        monitored_property_array_index: None,
        cov_increment: None,
        notification_kind: kind,
        timestamped: false,
    }
}
fn value(v: f32) -> CovObservation {
    CovObservation::new(CovSample::new(&PropertyValue::Real(v)).unwrap(), None).unwrap()
}
#[test]
fn cov_order_counter_checked_exhaustion_covers_both_modes() {
    let mut table = CovSubscriptionTable::new();
    let sub = table
        .subscribe(proposal(CovNotificationKind::Single, false))
        .unwrap();
    let mut other = proposal(CovNotificationKind::Single, true);
    other.subscriber_process_identifier = 2;
    let confirmed = table.subscribe(other).unwrap();
    let first = confirmed.prepare_completion().unwrap();
    assert!(
        matches!(first, PreparedCovCompletion::Confirmed(ticket) if ticket.get() == 1),
        "confirmed reports draw from the same counter (#896)"
    );
    table.owner.issued.store(u64::MAX - 1, Ordering::Relaxed);
    let final_ticket = sub.prepare_completion().unwrap();
    assert!(table.complete_observation(&sub, final_ticket, value(10.0)));
    assert_eq!(
        table
            .get_subscription(sub.key())
            .unwrap()
            .last_successful_ticket,
        u64::MAX
    );
    assert!(sub.prepare_completion().is_none());
    assert!(confirmed.prepare_completion().is_none());
    assert_eq!(table.owner.issued.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(
        table
            .get_subscription(sub.key())
            .unwrap()
            .last_notified_observation,
        Some(value(10.0))
    );
    let flight = table.begin_confirmed([(&confirmed, first)]).unwrap();
    assert!(
        !table.complete_observation(&confirmed, final_ticket, value(30.0)),
        "mode mismatch fails closed"
    );
    assert!(table.complete_observation(&confirmed, first, value(20.0)));
    drop(flight);
    assert_eq!(
        table
            .get_subscription(confirmed.key())
            .unwrap()
            .last_notified_observation,
        Some(value(20.0))
    );
}
#[test]
fn cov_order_successful_marker_is_live_per_reference_and_resets_on_replacement() {
    let mut table = CovSubscriptionTable::new();
    let p = proposal(CovNotificationKind::Single, false);
    let first = table.subscribe(p.clone()).unwrap();
    let older = first.prepare_completion().unwrap();
    let newer = first.prepare_completion().unwrap();
    assert!(table.complete_observation(&first, newer, value(20.0)));
    assert!(!table.complete_observation(&first, older, value(10.0)));
    assert!(
        !table.complete_observation(&first, newer, value(30.0)),
        "duplicate success cannot republish"
    );
    let clone = first.clone(); // Its copied successful marker remains stale/empty.
    let latest = clone.prepare_completion().unwrap();
    assert!(table.complete_observation(&clone, latest, value(40.0)));
    assert_eq!(
        table
            .get_subscription(first.key())
            .unwrap()
            .last_notified_observation,
        Some(value(40.0))
    );
    let replacement = table.subscribe(p).unwrap();
    assert_eq!(replacement.last_successful_ticket, 0);
    assert!(!table.complete_observation(&first, latest, value(50.0)));
    assert!(table.complete_observation(
        &replacement,
        replacement.prepare_completion().unwrap(),
        value(60.0)
    ));
    let mut other_proposal = proposal(CovNotificationKind::Single, false);
    other_proposal.subscriber_process_identifier = 2;
    let sibling = table.subscribe(other_proposal).unwrap();
    let a = sibling.prepare_completion().unwrap();
    let b = replacement.prepare_completion().unwrap();
    assert!(table.complete_observation(&replacement, b, value(70.0)));
    assert!(
        table.complete_observation(&sibling, a, value(5.0)),
        "other references do not share successful progress"
    );
    let mut foreign = CovSubscriptionTable::new();
    let foreign_sub = foreign
        .subscribe(proposal(CovNotificationKind::Single, false))
        .unwrap();
    assert!(!table.complete_observation(
        &foreign_sub,
        foreign_sub.prepare_completion().unwrap(),
        value(100.0)
    ));
}
#[test]
fn cov_order_multiple_expiry_refresh_retains_progress_and_route_change_fences() {
    let mut table = CovSubscriptionTable::new();
    let mut p = proposal(CovNotificationKind::Multiple, false);
    p.subscriber_network = Some(bacnet_encoding::npdu::NpduAddress {
        network: 7,
        mac_address: MacAddr::from_slice(&[9]),
    });
    let first = table.admit_for_test(p.clone(), 0).unwrap();
    let older = first.prepare_completion().unwrap();
    let newer = first.prepare_completion().unwrap();
    assert!(table.complete_observation(&first, newer, value(20.0)));
    let context = first.key().multiple_context().unwrap().clone();
    table
        .subscribe_multiple(
            &context,
            &first.endpoint(),
            Instant::now() + Duration::from_secs(120),
            5,
            vec![],
        )
        .unwrap();
    assert!(!table.complete_observation(&first, older, value(10.0)));
    assert_eq!(
        table
            .get_subscription(first.key())
            .unwrap()
            .last_notified_observation,
        Some(value(20.0))
    );
    let issued = first.prepare_completion().unwrap();
    let mut route = first.endpoint();
    route.mac = MacAddr::from_slice(&[2]);
    table
        .subscribe_multiple(
            &context,
            &route,
            Instant::now() + Duration::from_secs(120),
            5,
            vec![],
        )
        .unwrap();
    assert!(!table.complete_observation(&first, issued, value(30.0)));
    let moved = table.get_subscription(first.key()).unwrap().clone();
    assert!(table.complete_observation(&moved, moved.prepare_completion().unwrap(), value(40.0)));
    assert!(table.unsubscribe(moved.key()));
    assert!(!table.complete_observation(&moved, moved.prepare_completion().unwrap(), value(50.0)));
    p.subscriber_mac = route.mac;
    let recreated = table.admit_for_test(p, 0).unwrap();
    assert_eq!(recreated.last_successful_ticket, 0);
    assert!(!table.complete_observation(&moved, moved.prepare_completion().unwrap(), value(50.0)));
}

fn baseline(table: &CovSubscriptionTable, sub: &CovSubscriptionSnapshot) -> Option<CovObservation> {
    table
        .get_subscription(sub.key())
        .unwrap()
        .last_notified_observation
        .clone()
}
fn live(table: &CovSubscriptionTable, sub: &CovSubscriptionSnapshot) -> CovSubscriptionSnapshot {
    table.get_subscription(sub.key()).unwrap().clone()
}
#[test]
fn cov_confirmed_completion_needs_its_outstanding_report() {
    let mut table = CovSubscriptionTable::new();
    let sub = table
        .subscribe(proposal(CovNotificationKind::Single, true))
        .unwrap();
    let report = sub.prepare_completion().unwrap();
    assert!(
        !table.complete_observation(&sub, report, value(10.0)),
        "no outstanding report, no completion"
    );
    let flight = table.begin_confirmed([(&sub, report)]).unwrap();
    assert!(!table.confirmed_idle(&sub));
    let later = sub.prepare_completion().unwrap();
    assert!(
        table.begin_confirmed([(&sub, later)]).is_none(),
        "one outstanding report per reference"
    );
    assert!(!table.complete_observation(&sub, later, value(20.0)));
    // Retries exhausted, an Error or shutdown: the baseline stays put and the
    // reference may report again.
    drop(flight);
    assert_eq!(baseline(&table, &sub), None);
    assert!(table.confirmed_idle(&sub));
    assert!(!table.complete_observation(&sub, report, value(10.0)));

    let flight = table.begin_confirmed([(&sub, later)]).unwrap();
    assert!(table.complete_observation(&sub, later, value(20.0)));
    assert_eq!(baseline(&table, &sub), Some(value(20.0)));
    assert!(
        !table.confirmed_idle(&sub),
        "a snapshot older than the Ack no longer holds the live baseline"
    );
    let current = live(&table, &sub);
    assert!(table.confirmed_idle(&current), "the Ack cleared the mark");
    let next = current.prepare_completion().unwrap();
    assert!(table.begin_confirmed([(&sub, next)]).is_none());
    let next_flight = table.begin_confirmed([(&current, next)]).unwrap();
    drop(flight);
    assert!(
        !table.confirmed_idle(&current),
        "an acknowledged report cannot clear its successor's mark"
    );
    drop(next_flight);
    assert!(table.confirmed_idle(&current));
}
#[test]
fn cov_confirmed_replaced_report_cannot_touch_the_replacement() {
    let mut table = CovSubscriptionTable::new();
    let p = proposal(CovNotificationKind::Single, true);
    let first = table.subscribe(p.clone()).unwrap();
    let old = first.prepare_completion().unwrap();
    let old_flight = table.begin_confirmed([(&first, old)]).unwrap();
    let replacement = table.subscribe(p).unwrap();
    assert!(
        table.confirmed_idle(&replacement),
        "a replacement starts without an outstanding report"
    );
    let new = replacement.prepare_completion().unwrap();
    let new_flight = table.begin_confirmed([(&replacement, new)]).unwrap();
    assert!(!table.complete_observation(&first, old, value(10.0)));
    drop(old_flight);
    assert_eq!(baseline(&table, &replacement), None);
    assert!(
        !table.confirmed_idle(&replacement),
        "the stale report left the replacement's mark alone"
    );
    assert!(table.complete_observation(&replacement, new, value(20.0)));
    drop(new_flight);
    assert_eq!(baseline(&table, &replacement), Some(value(20.0)));
}
#[test]
fn cov_confirmed_multiple_route_change_fences_the_old_report() {
    let mut table = CovSubscriptionTable::new();
    let mut first = proposal(CovNotificationKind::Multiple, true);
    first.subscriber_network = Some(bacnet_encoding::npdu::NpduAddress {
        network: 7,
        mac_address: MacAddr::from_slice(&[9]),
    });
    let mut second = first.clone();
    second.monitored_property = Some(PropertyIdentifier::STATUS_FLAGS);
    let a = table.admit_for_test(first, 0).unwrap();
    let b = table.admit_for_test(second, 0).unwrap();
    let solo = table
        .begin_confirmed([(&b, b.prepare_completion().unwrap())])
        .unwrap();
    let (ta, tb) = (
        a.prepare_completion().unwrap(),
        b.prepare_completion().unwrap(),
    );
    assert!(table.begin_confirmed([(&a, ta), (&b, tb)]).is_none());
    assert!(
        table.confirmed_idle(&a),
        "all or none: b's outstanding report leaves a unmarked"
    );
    drop(solo);
    // One notification marks every reference it carries.
    let flight = table.begin_confirmed([(&a, ta), (&b, tb)]).unwrap();
    assert!(!table.confirmed_idle(&a) && !table.confirmed_idle(&b));
    let context = a.key().multiple_context().unwrap().clone();
    let expires = Instant::now() + Duration::from_secs(120);
    // Same-route refresh keeps the report's authority.
    table
        .subscribe_multiple(&context, &a.endpoint(), expires, 5, vec![])
        .unwrap();
    assert!(table.complete_observation(&a, ta, value(1.0)));
    let mut route = a.endpoint();
    route.mac = MacAddr::from_slice(&[2]);
    table
        .subscribe_multiple(&context, &route, expires, 5, vec![])
        .unwrap();
    assert!(
        !table.complete_observation(&b, tb, value(2.0)),
        "an old-route report cannot complete the moved reference"
    );
    let moved = live(&table, &b);
    assert!(
        table.confirmed_idle(&moved),
        "the new route starts without the old route's mark"
    );
    let d = moved.prepare_completion().unwrap();
    let moved_flight = table.begin_confirmed([(&moved, d)]).unwrap();
    drop(flight);
    assert!(!table.confirmed_idle(&moved));
    assert!(table.complete_observation(&moved, d, value(3.0)));
    drop(moved_flight);
    assert_eq!(baseline(&table, &a), Some(value(1.0)));
    assert_eq!(baseline(&table, &b), Some(value(3.0)));
}
#[tokio::test]
async fn cov_revisits_drain_once_and_forget_removed_references() {
    let mut table = CovSubscriptionTable::new();
    let a = table
        .subscribe(proposal(CovNotificationKind::Single, true))
        .unwrap();
    let mut other = proposal(CovNotificationKind::Single, true);
    other.subscriber_process_identifier = 2;
    let b = table.subscribe(other).unwrap();
    let revisits = Arc::clone(table.revisits());
    revisits.request([a.key().clone(), b.key().clone(), a.key().clone()]);
    assert!(table.unsubscribe(b.key()));
    assert_eq!(revisits.next().await, vec![a.key().clone()]);
    revisits.request([a.key().clone()]);
    assert_eq!(revisits.next().await, vec![a.key().clone()]);
}
