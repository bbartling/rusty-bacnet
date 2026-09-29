use super::*;
use crate::cov::{CovRecipient, CovSample};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{Date, ObjectIdentifier, PropertyValue, Time};
use bacnet_types::MacAddr;

fn context(process_id: u32) -> MultipleContextKey {
    MultipleContextKey {
        recipient: CovRecipient::Direct(MacAddr::from_slice(&[10, 0, 0, 1, 0xBA, 0xC0])),
        process_id,
        confirmed: false,
    }
}

fn key(process_id: u32, instance: u32) -> CovSubscriptionKey {
    CovSubscriptionKey::Multiple {
        context: context(process_id),
        object: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, instance).unwrap(),
        property: PropertyIdentifier::PRESENT_VALUE,
        index: None,
    }
}

fn frame(second: u8) -> ClockFrame {
    ClockFrame {
        local_date: Date {
            year: 126,
            month: 9,
            day: 29,
            day_of_week: 2,
        },
        local_time: Time {
            hour: 14,
            minute: 0,
            second,
            hundredths: 0,
        },
        utc_offset: 0,
        daylight_savings_status: false,
    }
}

/// A change whose single value occupies `payload` octets.
fn change(second: u8, payload: usize) -> TimedChange {
    let sample = CovSample::new(&PropertyValue::Real(f32::from(second))).unwrap();
    TimedChange::new(
        frame(second),
        vec![COVNotificationValue {
            property_identifier: PropertyIdentifier::PRESENT_VALUE,
            property_array_index: None,
            value: vec![0; payload],
            time_of_change: None,
        }],
        CovObservation::new(sample, None).unwrap(),
    )
}

fn seconds(changes: &[TimedChange]) -> Vec<u8> {
    changes
        .iter()
        .map(|c| c.frame().local_time.second)
        .collect()
}

/// Capacity for exactly `n` changes of `payload` octets in one context.
fn histories(n: usize, payload: usize) -> (TimedHistories, Arc<AtomicCovCounters>) {
    let counters = Arc::new(AtomicCovCounters::default());
    let capacity = n * (payload + VALUE_FRAMING);
    (
        TimedHistories::new(capacity, Arc::clone(&counters)),
        counters,
    )
}

fn store(n: usize, payload: usize) -> (TimedStore, Arc<AtomicCovCounters>) {
    let counters = Arc::new(AtomicCovCounters::default());
    let apdu = ENVELOPE_RESERVE + n * (payload + VALUE_FRAMING);
    (TimedStore::new(apdu, Arc::clone(&counters)), counters)
}

fn dropped(counters: &AtomicCovCounters) -> u64 {
    counters.timed_changes_dropped.load(Ordering::Relaxed)
}

#[test]
fn values_carry_their_own_change_time_and_queue_in_capture_order() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 7);
    h.push(&k, 7, change(1, 4));
    h.push(&k, 7, change(2, 4));
    assert_eq!(h.baseline(&k, 7), Some(change(2, 4).observation()));
    let drained = h.drain(&k, 7).1;
    assert_eq!(seconds(&drained), [1, 2]);
    assert_eq!(
        drained[0].values()[0].time_of_change,
        Some(frame(1).local_time)
    );
    assert!(h.drain(&k, 7).1.is_empty(), "drain retires the queue");
    assert_eq!(h.baseline(&k, 7), Some(change(2, 4).observation()));
}

#[test]
fn overflow_evicts_the_oldest_change_of_the_same_reference_and_counts_it() {
    let (mut h, counters) = histories(2, 4);
    let k = key(1, 1);
    h.reset(&k, 1);
    for second in 1..=3 {
        h.push(&k, 1, change(second, 4));
    }
    assert_eq!(seconds(&h.drain(&k, 1).1), [2, 3]);
    assert_eq!(dropped(&counters), 1);
}

#[test]
fn overflow_evicts_the_oldest_in_the_context_but_never_a_lone_newest_change() {
    let (mut h, counters) = histories(2, 4);
    let (a, b, other) = (key(1, 1), key(1, 2), key(2, 1));
    for k in [&a, &b, &other] {
        h.reset(k, 1);
    }
    h.push(&other, 1, change(9, 4)); // another context is never charged
    h.push(&a, 1, change(1, 4));
    h.push(&a, 1, change(2, 4));
    h.push(&b, 1, change(3, 4));
    assert_eq!(seconds(&h.drain(&a, 1).1), [2]);
    assert_eq!(seconds(&h.drain(&b, 1).1), [3]);
    assert_eq!(seconds(&h.drain(&other, 1).1), [9]);
    assert_eq!(dropped(&counters), 1);

    // A single change larger than the bound is still retained.
    let (mut h, counters) = histories(1, 4);
    h.reset(&a, 1);
    h.push(&a, 1, change(5, 64));
    assert_eq!(seconds(&h.drain(&a, 1).1), [5]);
    assert_eq!(dropped(&counters), 0);
}

#[test]
fn dropped_claim_requeues_ahead_of_newer_changes_and_commit_retires() {
    let (store, _) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 3);
    store.lock().push(&k, 3, change(1, 4));
    store.lock().push(&k, 3, change(2, 4));

    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 3);
    claim.add(k.clone(), incarnation, drained);
    assert_eq!(claim.earlier().len(), 1);
    assert_eq!(claim.latest(&k).map(|c| c.frame()), Some(frame(2)));
    assert_eq!(claim.last_frame(), Some(frame(2)));
    store.lock().push(&k, 3, change(3, 4));
    drop(claim);
    assert_eq!(seconds(&store.lock().drain(&k, 3).1), [1, 2, 3]);

    store.lock().push(&k, 3, change(4, 4));
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 3);
    claim.add(k.clone(), incarnation, drained);
    claim.commit();
    assert!(store.lock().drain(&k, 3).1.is_empty());
}

#[test]
fn stale_generations_and_cancelled_references_keep_nothing() {
    let (store, _) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1);
    store.lock().push(&k, 1, change(1, 4));
    assert!(
        store.lock().drain(&k, 2).1.is_empty(),
        "stale generation drains nothing"
    );
    store.lock().reset(&k, 2); // renewal publishes a new generation
    assert_eq!(store.lock().baseline(&k, 2), None);
    store.lock().push(&k, 1, change(5, 4)); // stale capture is ignored
    assert_eq!(seconds(&store.lock().drain(&k, 2).1), [1]);

    store.lock().push(&k, 2, change(6, 4));
    store.lock().remove(&k);
    store.lock().push(&k, 2, change(7, 4));
    assert!(
        store.lock().drain(&k, 2).1.is_empty(),
        "removed reference keeps nothing"
    );
}

#[test]
fn a_failed_notification_returns_changes_across_renewal_but_not_recreation() {
    let (store, _) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1);
    store.lock().push(&k, 1, change(1, 4));
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    claim.add(k.clone(), incarnation, drained);
    store.lock().reset(&k, 2); // renewal while the notification is in flight
    drop(claim);
    assert_eq!(seconds(&store.lock().drain(&k, 2).1), [1]);

    store.lock().push(&k, 2, change(2, 4));
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 2);
    claim.add(k.clone(), incarnation, drained);
    store.lock().remove(&k); // cancelled and subscribed again
    store.lock().reset(&k, 3);
    drop(claim);
    assert!(
        store.lock().drain(&k, 3).1.is_empty(),
        "a recreated reference never receives the old subscription's changes"
    );
}

#[test]
fn another_references_lone_newest_change_is_never_evicted() {
    let (mut h, counters) = histories(1, 4);
    let (a, b) = (key(1, 1), key(1, 2));
    for k in [&a, &b] {
        h.reset(k, 1);
    }
    h.push(&a, 1, change(1, 4));
    h.push(&b, 1, change(2, 4));
    assert_eq!(seconds(&h.drain(&a, 1).1), [1]);
    assert_eq!(seconds(&h.drain(&b, 1).1), [2]);
    assert_eq!(dropped(&counters), 0);
}

#[test]
fn renewal_keeps_pending_changes_and_recaptures_its_baseline() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1);
    h.push(&k, 1, change(1, 4));
    h.reset(&k, 2);
    assert_eq!(h.baseline(&k, 2), None);
    assert_eq!(seconds(&h.drain(&k, 2).1), [1]);
}

#[test]
fn failed_older_notification_cannot_requeue_behind_a_transmitted_newer_one() {
    let (store, counters) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1);
    store.lock().push(&k, 1, change(1, 4));
    let mut first = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    first.add(k.clone(), incarnation, drained);

    store.lock().push(&k, 1, change(2, 4));
    let mut second = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    second.add(k.clone(), incarnation, drained);
    second.commit();

    drop(first); // its send failed after the newer change was delivered
    assert!(store.lock().drain(&k, 1).1.is_empty());
    assert_eq!(dropped(&counters), 1);
}

#[test]
fn trimming_a_claim_discards_oldest_superseded_history_but_keeps_latest_changes() {
    let (store, counters) = store(8, 4);
    let (a, b) = (key(1, 1), key(1, 2));
    let mut claim = TimedClaim::new(store.clone());
    let mut changes_a: Vec<_> = (1..=3).map(|s| change(s, 4)).collect();
    for (seq, c) in changes_a.iter_mut().enumerate() {
        c.seq = seq as u64 + 1;
    }
    let mut changes_b: Vec<_> = [9, 10].into_iter().map(|s| change(s, 4)).collect();
    changes_b[0].seq = 9;
    changes_b[1].seq = 10;
    claim.add(a.clone(), 1, changes_a);
    claim.add(b.clone(), 1, changes_b);
    let order = |claim: &TimedClaim| {
        claim
            .earlier()
            .iter()
            .map(|(_, c)| c.frame().local_time.second)
            .collect::<Vec<_>>()
    };
    assert_eq!(order(&claim), [1, 2, 9]);
    assert!(claim.drop_oldest_earlier());
    assert_eq!(order(&claim), [2, 9], "oldest across the claim goes first");
    assert!(claim.drop_oldest_earlier());
    assert!(claim.drop_oldest_earlier());
    assert!(
        !claim.drop_oldest_earlier(),
        "latest changes are never trimmed"
    );
    assert_eq!(claim.latest(&a).map(|c| c.frame()), Some(frame(3)));
    assert_eq!(claim.latest(&b).map(|c| c.frame()), Some(frame(10)));
    assert_eq!(dropped(&counters), 3);
    claim.commit();
}

#[test]
fn a_reference_evicts_its_own_oldest_change_before_a_siblings() {
    let (mut h, counters) = histories(3, 4);
    let (a, b) = (key(1, 1), key(1, 2));
    for k in [&a, &b] {
        h.reset(k, 1);
    }
    h.push(&b, 1, change(1, 4));
    h.push(&b, 1, change(2, 4));
    h.push(&a, 1, change(3, 4));
    h.push(&a, 1, change(4, 4)); // over the bound: a's own oldest goes
    assert_eq!(seconds(&h.drain(&a, 1).1), [4]);
    assert_eq!(seconds(&h.drain(&b, 1).1), [1, 2]);
    assert_eq!(dropped(&counters), 1);
}

#[test]
fn a_returned_older_change_waits_for_its_in_flight_successor() {
    let (store, counters) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1);
    store.lock().push(&k, 1, change(1, 4));
    let mut older = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    older.add(k.clone(), incarnation, drained);
    store.lock().push(&k, 1, change(2, 4));
    let mut newer = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    newer.add(k.clone(), incarnation, drained);

    drop(older); // failed first, while the newer change is in flight
    assert!(
        store.lock().drain(&k, 1).1.is_empty(),
        "an older change is never conveyed as the latest state"
    );
    newer.commit();
    assert!(store.lock().drain(&k, 1).1.is_empty(), "superseded");
    assert_eq!(dropped(&counters), 1);

    // Had the newer notification failed as well, both return in order.
    store.lock().push(&k, 1, change(3, 4));
    let mut third = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    third.add(k.clone(), incarnation, drained);
    store.lock().push(&k, 1, change(4, 4));
    let mut fourth = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    fourth.add(k.clone(), incarnation, drained);
    drop(third);
    drop(fourth);
    assert_eq!(seconds(&store.lock().drain(&k, 1).1), [3, 4]);
}
