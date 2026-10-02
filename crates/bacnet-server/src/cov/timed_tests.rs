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

/// Octets one change of `payload` octets counts against its context's bound.
fn change_len(payload: usize) -> usize {
    change(0, payload).cost
}

/// A maximum APDU whose context bound holds exactly `n` changes of `payload`
/// octets, with no reserve.
fn apdu_for(n: usize, payload: usize) -> usize {
    let octets = n * change_len(payload);
    assert_eq!(octets % HISTORY_NOTIFICATIONS, 0, "an exact bound");
    ENVELOPE_RESERVE + octets / HISTORY_NOTIFICATIONS
}

/// Capacity for exactly `n` changes of `payload` octets in one context.
fn histories(n: usize, payload: usize) -> (TimedHistories, Arc<AtomicCovCounters>) {
    let counters = Arc::new(AtomicCovCounters::default());
    (
        TimedHistories::new(apdu_for(n, payload), Arc::clone(&counters)),
        counters,
    )
}

fn store(n: usize, payload: usize) -> (TimedStore, Arc<AtomicCovCounters>) {
    let counters = Arc::new(AtomicCovCounters::default());
    (
        TimedStore::new(apdu_for(n, payload), Arc::clone(&counters)),
        counters,
    )
}

fn dropped(counters: &AtomicCovCounters) -> u64 {
    counters.timed_changes_dropped.load(Ordering::Relaxed)
}

#[test]
fn values_carry_their_own_change_time_and_queue_in_capture_order() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 7, 0);
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
    h.reset(&k, 1, 0);
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
        h.reset(k, 1, 0);
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
    h.reset(&a, 1, 0);
    h.push(&a, 1, change(5, 64));
    assert_eq!(seconds(&h.drain(&a, 1).1), [5]);
    assert_eq!(dropped(&counters), 0);
}

#[test]
fn dropped_claim_requeues_ahead_of_newer_changes_and_commit_retires() {
    let (store, _) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 3, 0);
    store.lock().push(&k, 3, change(1, 4));
    store.lock().push(&k, 3, change(2, 4));

    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 3);
    claim.add(k.clone(), incarnation, drained);
    assert_eq!(claim.earlier().len(), 1);
    assert_eq!(claim.latest(&k).map(|c| c.frame()), Some(frame(2)));
    assert_eq!(claim.newest().map(|(_, f)| f), Some(frame(2)));
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
    store.lock().reset(&k, 1, 0);
    store.lock().push(&k, 1, change(1, 4));
    assert!(
        store.lock().drain(&k, 2).1.is_empty(),
        "stale generation drains nothing"
    );
    store.lock().reset(&k, 2, 0); // renewal publishes a new generation
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
    store.lock().reset(&k, 1, 0);
    store.lock().push(&k, 1, change(1, 4));
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    claim.add(k.clone(), incarnation, drained);
    store.lock().reset(&k, 2, 0); // renewal while the notification is in flight
    drop(claim);
    assert_eq!(seconds(&store.lock().drain(&k, 2).1), [1]);

    store.lock().push(&k, 2, change(2, 4));
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 2);
    claim.add(k.clone(), incarnation, drained);
    store.lock().remove(&k); // cancelled and subscribed again
    store.lock().reset(&k, 3, 0);
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
        h.reset(k, 1, 0);
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
    h.reset(&k, 1, 0);
    h.push(&k, 1, change(1, 4));
    h.reset(&k, 2, 0);
    assert_eq!(h.baseline(&k, 2), None);
    assert_eq!(seconds(&h.drain(&k, 2).1), [1]);
}

/// A change whose PV value encodes as four `byte` octets.
fn valued(second: u8, byte: u8) -> TimedChange {
    let mut change = change(second, 4);
    change.values[0].value = vec![byte; 4];
    change
}

/// How `h` times the own field of `k`'s `generation` carried as four `byte`
/// octets, with `now` as the preparation clock.
fn timing(
    h: &mut TimedHistories,
    k: &CovSubscriptionKey,
    generation: u64,
    byte: u8,
    now: Option<ClockFrame>,
) -> FieldTiming {
    h.field_time(k, generation, &[byte; 4], || now)
}

/// The clock frame of an `At` timing.
fn at_frame(timing: FieldTiming) -> Option<ClockFrame> {
    match timing {
        FieldTiming::At(_, frame) => Some(frame),
        _ => None,
    }
}

#[test]
fn a_field_keeps_its_captured_time_and_remembers_one_for_an_uncaptured_value() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 0);
    assert_eq!(timing(&mut h, &k, 1, 1, None), FieldTiming::NoTime);
    h.push(&k, 1, valued(3, 1));
    let captured = timing(&mut h, &k, 1, 1, Some(frame(9)));
    assert_eq!(
        at_frame(captured),
        Some(frame(3)),
        "the captured value's time"
    );
    // A value no capture recorded takes the preparation time, once.
    assert_eq!(
        timing(&mut h, &k, 1, 2, None),
        FieldTiming::NoTime,
        "left out"
    );
    let moved = timing(&mut h, &k, 1, 2, Some(frame(9)));
    assert_eq!(at_frame(moved), Some(frame(9)));
    let (FieldTiming::At(old, _), FieldTiming::At(new, _)) = (captured, moved) else {
        unreachable!()
    };
    assert!(new > old, "newer than the captured change");
    assert_eq!(
        timing(&mut h, &k, 1, 2, Some(frame(12))),
        moved,
        "remembered"
    );
    assert_eq!(
        h.baseline(&k, 1),
        Some(valued(3, 1).observation()),
        "the increment baseline is untouched"
    );
    // A reference that is no longer live owns nothing.
    assert_eq!(
        timing(&mut h, &k, 2, 2, Some(frame(12))),
        FieldTiming::NotLive
    );
    h.remove(&k);
    assert_eq!(
        timing(&mut h, &k, 1, 2, Some(frame(12))),
        FieldTiming::NotLive
    );
}

#[test]
fn a_capture_below_the_increment_records_the_value_at_its_commit_time() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 0);
    h.push(&k, 1, valued(3, 1)); // A, captured
    h.note_field(&k, 1, &valued(5, 2).values, frame(5)); // B, below the increment
    assert_eq!(at_frame(timing(&mut h, &k, 1, 2, None)), Some(frame(5)));
    h.note_field(&k, 1, &valued(7, 2).values, frame(7)); // still B
    assert_eq!(at_frame(timing(&mut h, &k, 1, 2, None)), Some(frame(5)));
    h.note_field(&k, 1, &valued(9, 1).values, frame(9)); // A again
    assert_eq!(
        at_frame(timing(&mut h, &k, 1, 1, None)),
        Some(frame(9)),
        "A-B-A: the second A's time, not the first's"
    );
    assert_eq!(h.baseline(&k, 1), Some(valued(3, 1).observation()));
    h.note_field(&k, 2, &valued(11, 3).values, frame(11)); // a stale generation
    assert_eq!(timing(&mut h, &k, 1, 3, None), FieldTiming::NoTime);
}

#[test]
fn a_field_time_follows_renewal_captures_and_a_recreated_reference_starts_fresh() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 0);
    h.push(&k, 1, valued(3, 1));
    h.reset(&k, 2, 0); // a renewal
    let at = |h: &mut TimedHistories, generation| at_frame(timing(h, &k, generation, 1, None));
    assert_eq!(at(&mut h, 2), Some(frame(3)), "until the renewal's capture");
    h.push(&k, 2, valued(5, 1)); // its initial report, the same value
    assert_eq!(
        at(&mut h, 2),
        Some(frame(5)),
        "a renewal capture is a change"
    );
    h.remove(&k); // cancelled, then subscribed again
    h.reset(&k, 3, 0);
    assert_eq!(at(&mut h, 3), None, "a recreated reference starts fresh");
}

#[test]
fn failed_older_notification_cannot_requeue_behind_a_transmitted_newer_one() {
    let (store, counters) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1, 0);
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

/// A claim of `a`'s changes at seconds 1, 2, 3 and `b`'s at 9 and 10, each
/// sequenced by its second.
fn two_reference_claim(store: &TimedStore) -> (TimedClaim, CovSubscriptionKey, CovSubscriptionKey) {
    let (a, b) = (key(1, 1), key(1, 2));
    let sequenced = |seconds: &[u8]| {
        seconds
            .iter()
            .map(|&second| {
                let mut change = change(second, 4);
                change.seq = u64::from(second);
                change
            })
            .collect::<Vec<_>>()
    };
    let mut claim = TimedClaim::new(store.clone());
    claim.add(a.clone(), 1, sequenced(&[1, 2, 3]));
    claim.add(b.clone(), 1, sequenced(&[9, 10]));
    (claim, a, b)
}

fn history_seconds(claim: &TimedClaim) -> Vec<u8> {
    claim
        .earlier()
        .iter()
        .map(|(_, c)| c.frame().local_time.second)
        .collect()
}

#[test]
fn splitting_moves_the_oldest_history_and_keeps_every_latest_change() {
    let (store, counters) = store(8, 4);
    let (mut claim, a, b) = two_reference_claim(&store);
    assert_eq!(history_seconds(&claim), [1, 2, 9]);
    assert!(history_seconds(&claim.split_earliest(0)).is_empty());

    let part = claim.split_earliest(2);
    assert_eq!(history_seconds(&part), [1, 2], "every change is history");
    assert_eq!(part.latest(&a).map(|c| c.frame()), None);
    assert_eq!(
        part.newest().map(|(_, f)| f),
        Some(frame(2)),
        "named after its last"
    );
    assert_eq!(history_seconds(&claim), [9], "the oldest across the claim");
    assert_eq!(claim.latest(&a).map(|c| c.frame()), Some(frame(3)));
    assert_eq!(claim.latest(&b).map(|c| c.frame()), Some(frame(10)));

    // Asking for more than there is moves every earlier change, never a
    // reference's latest.
    let rest = claim.split_earliest(5);
    assert_eq!(history_seconds(&rest), [9]);
    assert!(history_seconds(&claim).is_empty());
    assert_eq!(claim.newest().map(|(_, f)| f), Some(frame(10)));
    assert_eq!(
        claim
            .last_changes()
            .map(|(_, c)| c.frame().local_time.second)
            .collect::<Vec<_>>(),
        [3, 10]
    );
    drop((part, rest, claim));
    assert_eq!(dropped(&counters), 0, "splitting drops nothing");
}

#[test]
fn split_parts_retire_and_return_on_their_own_without_drops() {
    let (store, counters) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1, 0);
    for second in 1..=3 {
        store.lock().push(&k, 1, change(second, 4));
    }
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    claim.add(k.clone(), incarnation, drained);
    let first = claim.split_earliest(1);
    // A confirmed report sends the first part and returns the rest.
    drop(claim);
    first.commit();
    assert_eq!(seconds(&store.lock().drain(&k, 1).1), [2, 3]);

    // An unconfirmed report retires each part it sends; a later part that
    // fails returns only itself.
    store.lock().push(&k, 1, change(4, 4));
    store.lock().push(&k, 1, change(5, 4));
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    claim.add(k.clone(), incarnation, drained);
    let first = claim.split_earliest(1);
    first.commit();
    drop(claim);
    assert_eq!(seconds(&store.lock().drain(&k, 1).1), [5]);
    assert_eq!(dropped(&counters), 0);
}

#[test]
fn the_bound_spans_several_notifications_of_the_smaller_apdu_less_a_reserve() {
    let (mut h, counters) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 0);
    for second in 1..=8 {
        h.push(&k, 1, change(second, 4));
    }
    assert_eq!(dropped(&counters), 0, "eight changes fit the local bound");
    h.drain(&k, 1);

    // A subscriber with a smaller APDU shrinks the bound to two changes.
    let small = u16::try_from(apdu_for(2, 4)).unwrap();
    h.set_apdu(&context(1), Some(small));
    for second in 11..=13 {
        h.push(&k, 1, change(second, 4));
    }
    assert_eq!(seconds(&h.drain(&k, 1).1), [12, 13]);
    assert_eq!(dropped(&counters), 1);

    // A larger one cannot exceed the local maximum, nor can an unknown one.
    for subscriber in [Some(u16::MAX), None] {
        h.set_apdu(&context(1), subscriber);
        for second in 21..=29 {
            h.push(&k, 1, change(second, 4));
        }
        assert_eq!(h.drain(&k, 1).1.len(), 8, "{subscriber:?}");
    }
    assert_eq!(dropped(&counters), 3);

    // Room the untimestamped values took is kept for them.
    h.note_reserve(&context(1), change_len(4));
    for second in 31..=38 {
        h.push(&k, 1, change(second, 4));
    }
    assert_eq!(seconds(&h.drain(&k, 1).1), [32, 33, 34, 35, 36, 37, 38]);
    assert_eq!(dropped(&counters), 4);
    // At most one notification's worth: two changes here.
    h.note_reserve(&context(1), 10 * change_len(4));
    for second in 41..=47 {
        h.push(&k, 1, change(second, 4));
    }
    assert_eq!(h.drain(&k, 1).1.len(), 6);
    assert_eq!(dropped(&counters), 5);
    // An admission starts the reserve over.
    h.set_apdu(&context(1), None);
    for second in 51..=58 {
        h.push(&k, 1, change(second, 4));
    }
    assert_eq!(h.drain(&k, 1).1.len(), 8);
    assert_eq!(dropped(&counters), 5);
}

#[test]
fn the_reserve_belongs_to_the_context_and_starts_over_when_it_loses_a_reference() {
    let (mut h, counters) = histories(8, 4);
    let (a, b) = (key(1, 1), key(1, 2));
    h.reset(&a, 1, 0);
    h.note_reserve(&context(1), change_len(4));
    h.reset(&b, 1, 0); // a later reference shares the context's reserve
    for second in 1..=8 {
        h.push(&b, 1, change(second, 4));
    }
    assert_eq!(
        dropped(&counters),
        1,
        "seven changes fit beside the reserve"
    );
    h.drain(&b, 1);
    h.remove(&a); // the context lost a reference: its reserve starts over
    for second in 11..=18 {
        h.push(&b, 1, change(second, 4));
    }
    assert_eq!(dropped(&counters), 1);
    h.remove(&b);
    assert_eq!(h.held(), (0, 0), "the last reference took the terms along");
}

#[test]
fn a_send_turn_holds_back_other_reports_and_owes_one_follow_up() {
    let (store, _) = store(8, 4);
    let revisits = Arc::new(crate::cov::CovRevisits::default());
    let k = key(1, 1);
    let begin = |context: MultipleContextKey, keys: Vec<CovSubscriptionKey>| {
        SendTurn::begin(&store, &context, &revisits, keys)
    };
    let turn = begin(context(1), vec![k.clone()]).expect("free");
    assert!(
        begin(context(1), vec![k.clone()]).is_none(),
        "one at a time"
    );
    drop(begin(context(2), vec![key(2, 1)]).expect("per context"));
    assert!(
        revisits.queued().is_empty(),
        "nobody stood back from context 2"
    );
    drop(turn);
    assert_eq!(
        revisits.queued(),
        std::collections::HashSet::from([k.clone()]),
        "the report that stood back gets one follow-up"
    );
    drop(begin(context(1), vec![k.clone()]).expect("free again"));
}

#[test]
fn deferred_parts_return_without_eviction_and_discarded_ones_are_counted() {
    let (store, counters) = store(2, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1, 0);
    store.lock().push(&k, 1, change(1, 4));
    store.lock().push(&k, 1, change(2, 4));
    let mut claim = TimedClaim::new(store.clone());
    let (incarnation, drained) = store.lock().drain(&k, 1);
    claim.add(k.clone(), incarnation, drained);
    store.lock().push(&k, 1, change(3, 4));
    // Back over the bound, but a deferred part is not evicted.
    drop(claim.without_eviction());
    assert_eq!(dropped(&counters), 0);
    let (incarnation, drained) = store.lock().drain(&k, 1);
    assert_eq!(seconds(&drained), [1, 2, 3]);
    let mut claim = TimedClaim::new(store.clone());
    claim.add(k.clone(), incarnation, drained);
    claim.split_earliest(1).discard("too large");
    assert_eq!(dropped(&counters), 1);
    drop(claim);
    assert_eq!(seconds(&store.lock().drain(&k, 1).1), [2, 3]);
}

#[test]
fn an_admission_without_a_known_maximum_apdu_keeps_the_one_advertised_before() {
    let mut table = crate::cov::CovSubscriptionTable::new();
    let route = crate::cov::SubscriberEndpoint::new(&[10, 0, 0, 1, 0xBA, 0xC0], None);
    let expires = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let sub = timed_reference(1, expires);
    let advertised = |table: &crate::cov::CovSubscriptionTable| {
        table
            .get_subscription(&sub.key().unwrap())
            .and_then(|entry| entry.subscriber_max_apdu())
    };
    table
        .subscribe_multiple(
            &context(1),
            &route,
            expires,
            10,
            Some(206),
            vec![sub.clone()],
        )
        .unwrap();
    assert_eq!(advertised(&table), Some(206));
    table
        .subscribe_multiple(&context(1), &route, expires, 10, None, Vec::new())
        .unwrap();
    assert_eq!(advertised(&table), Some(206), "an unknown one keeps it");
    table
        .subscribe_multiple(&context(1), &route, expires, 10, Some(480), Vec::new())
        .unwrap();
    assert_eq!(advertised(&table), Some(480), "a known one replaces it");
}

#[test]
fn a_reference_evicts_its_own_oldest_change_before_a_siblings() {
    let (mut h, counters) = histories(3, 4);
    let (a, b) = (key(1, 1), key(1, 2));
    for k in [&a, &b] {
        h.reset(k, 1, 0);
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
    store.lock().reset(&k, 1, 0);
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

fn sorted(mut keys: Vec<CovSubscriptionKey>) -> Vec<CovSubscriptionKey> {
    keys.sort_by_key(|key| key.object().instance_number());
    keys
}

#[tokio::test(start_paused = true)]
async fn a_context_is_due_at_its_delay_after_its_earliest_pending_change() {
    let (mut h, _) = histories(8, 4);
    let (a, b, other) = (key(1, 1), key(1, 2), key(2, 1));
    for k in [&a, &b, &other] {
        h.reset(k, 1, 0);
    }
    h.set_delay(&context(1), 10);
    h.set_delay(&context(2), 10);
    let start = Instant::now();
    h.push(&a, 1, change(1, 4));
    tokio::time::advance(Duration::from_secs(4)).await;
    h.push(&b, 1, change(2, 4));
    h.push(&other, 1, change(3, 4));
    let (due, next) = h.take_due(Instant::now());
    assert!(due.is_empty());
    assert_eq!(
        next,
        Some(start + Duration::from_secs(10)),
        "from the earliest"
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    let (due, next) = h.take_due(Instant::now());
    assert_eq!(
        sorted(due),
        [a, b],
        "every pending reference of the context"
    );
    assert_eq!(
        next,
        Some(start + Duration::from_secs(14)),
        "the other context"
    );
}

#[tokio::test(start_paused = true)]
async fn a_blocked_context_comes_back_only_after_its_spacing() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 0);
    h.set_delay(&context(1), 0);
    let start = Instant::now();
    h.push(&k, 1, change(1, 4));
    // A zero delay still waits out the floor, leaving the producer's own
    // fanout to report the change.
    let (due, next) = h.take_due(start);
    assert!(due.is_empty());
    assert_eq!(next, Some(start + DEADLINE_FLOOR));
    tokio::time::advance(DEADLINE_FLOOR).await;
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    // Still pending: not handed out again until the spacing has passed.
    let (due, next) = h.take_due(Instant::now());
    assert!(due.is_empty());
    assert_eq!(next, Some(start + DEADLINE_FLOOR * 2));
    tokio::time::advance(DEADLINE_FLOOR).await;
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    // Conveyed: nothing is owed and the spacing is forgotten.
    h.drain(&k, 1);
    assert_eq!(h.take_due(Instant::now()), (Vec::new(), None));
    assert_eq!(h.held(), (1, 0), "the wait went with the pending changes");
}

#[tokio::test(start_paused = true)]
async fn the_latest_admitted_delay_applies_until_the_context_goes() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 30);
    h.set_delay(&context(1), 3); // a renewal changes the delay
    let start = Instant::now();
    h.push(&k, 1, change(1, 4));
    assert_eq!(h.take_due(start).1, Some(start + Duration::from_secs(3)));
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    assert_eq!(h.held(), (1, 1));
    h.remove(&k);
    assert_eq!(h.held(), (0, 0), "the last reference took its wait along");
}

fn timed_reference(process_id: u32, expires_at: std::time::Instant) -> crate::cov::CovSubscription {
    crate::cov::CovSubscription {
        subscriber_mac: MacAddr::from_slice(&[10, 0, 0, 1, 0xBA, 0xC0]),
        subscriber_network: None,
        subscriber_process_identifier: process_id,
        monitored_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap(),
        issue_confirmed_notifications: false,
        expires_at: Some(expires_at),
        last_notified_observation: None,
        monitored_property: Some(PropertyIdentifier::PRESENT_VALUE),
        monitored_property_array_index: None,
        cov_increment: None,
        notification_kind: crate::cov::CovNotificationKind::Multiple,
        timestamped: true,
    }
}

#[test]
fn empty_admissions_of_unknown_contexts_leave_no_deadline_state() {
    let mut table = crate::cov::CovSubscriptionTable::new();
    let route = crate::cov::SubscriberEndpoint::new(&[10, 0, 0, 1, 0xBA, 0xC0], None);
    let expires = std::time::Instant::now() + std::time::Duration::from_secs(300);
    // A peer varying process and form across empty-list requests.
    for process_id in 0..64 {
        for confirmed in [false, true] {
            let context = MultipleContextKey {
                confirmed,
                ..context(process_id)
            };
            let accepted = table
                .subscribe_multiple(&context, &route, expires, 10, None, Vec::new())
                .unwrap();
            assert!(accepted.is_empty());
        }
    }
    assert_eq!(table.timed().lock().held(), (0, 0));
}

#[tokio::test(start_paused = true)]
async fn cancel_and_expiry_take_a_contexts_deadline_state_along() {
    let far = std::time::Instant::now() + std::time::Duration::from_secs(300);
    for expire in [false, true] {
        let mut table = crate::cov::CovSubscriptionTable::new();
        let sub = table.admit_for_test(timed_reference(1, far), 10).unwrap();
        table
            .timed()
            .hold_until(&context(1), Instant::now() + Duration::from_secs(5));
        assert_eq!(table.timed().lock().held(), (1, 1));
        if expire {
            table.expire_all_for_test();
            table.purge_expired();
        } else {
            assert!(table.unsubscribe(sub.key()));
        }
        assert_eq!(table.timed().lock().held(), (0, 0), "expire={expire}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_context_without_a_timestamped_history_holds_nothing() {
    let (mut h, _) = histories(8, 4);
    // An empty-list admission of an unknown context, and a hold-off on it.
    h.set_delay(&context(9), 10);
    h.hold_until(&context(9), Instant::now() + Duration::from_secs(5));
    h.rearm();
    assert_eq!(h.held(), (0, 0));
}

#[tokio::test(start_paused = true)]
async fn a_hold_off_moves_the_next_attempt_to_its_end() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 10);
    let start = Instant::now();
    h.push(&k, 1, change(1, 4));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    // Blocked by a hold-off ending at +12: no need to wait the delay again.
    h.hold_until(&context(1), start + Duration::from_secs(12));
    assert_eq!(
        h.take_due(Instant::now()).1,
        Some(start + Duration::from_secs(12))
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
}

#[tokio::test(start_paused = true)]
async fn rearming_or_a_shorter_delay_ends_the_wait_of_overdue_changes() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset(&k, 1, 10);
    h.push(&k, 1, change(1, 4));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    assert!(h.take_due(Instant::now()).0.is_empty(), "waiting the delay");
    // Communication came back: overdue changes go out at once.
    h.rearm();
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    // A renewal shortens the delay: the wait it set no longer applies.
    assert!(h.take_due(Instant::now()).0.is_empty());
    h.set_delay(&context(1), 2);
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    // A longer delay leaves the current wait alone.
    h.set_delay(&context(1), 20);
    assert!(h.take_due(Instant::now()).0.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_queued_change_wakes_the_deadline_wait() {
    let (store, _) = store(8, 4);
    let k = key(1, 1);
    store.lock().reset(&k, 1, 0);
    store.lock().set_delay(&context(1), 2);
    let waiter = tokio::spawn({
        let store = store.clone();
        async move { store.next_due().await }
    });
    tokio::task::yield_now().await;
    let start = Instant::now();
    store.lock().push(&k, 1, change(1, 4));
    assert_eq!(waiter.await.unwrap(), [k]);
    assert_eq!(start.elapsed(), Duration::from_secs(2));
}
