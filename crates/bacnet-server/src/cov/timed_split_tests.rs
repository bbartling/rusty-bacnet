//! Splitting claims, the per-context bound, send turns and the subscriber's
//! maximum APDU (#986), and owed untimestamped references (#1038).
use super::tests::{
    apdu_for, change, change_len, context, dropped, frame, histories, key, seconds, store,
    timed_reference,
};
use super::*;

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

fn claimed_seconds(claim: &TimedClaim) -> Vec<u8> {
    claim
        .in_order()
        .iter()
        .map(|(_, c)| c.frame().local_time.second)
        .collect()
}

#[test]
fn splitting_moves_the_oldest_changes_in_capture_order_latest_ones_included() {
    let (store, counters) = store(8, 4);
    let (mut claim, _, b) = two_reference_claim(&store);
    assert_eq!(claimed_seconds(&claim), [1, 2, 3, 9, 10]);
    assert!(claimed_seconds(&claim.split_oldest(0)).is_empty());

    let part = claim.split_oldest(2);
    assert_eq!(claimed_seconds(&part), [1, 2]);
    assert_eq!(claimed_seconds(&claim), [3, 9, 10]);

    // `a`'s latest change goes with `b`'s older one: capture order across
    // the claim decides, not whether a change is a reference's latest (#1008).
    let next = claim.split_oldest(2);
    assert_eq!(claimed_seconds(&next), [3, 9]);
    assert_eq!(
        next.last_changes()
            .map(|(_, c)| c.frame().local_time.second)
            .collect::<Vec<_>>(),
        [3, 9]
    );
    assert_eq!(
        claim
            .last_changes()
            .map(|(key, c)| (key.clone(), c.frame()))
            .collect::<Vec<_>>(),
        [(b, frame(10))],
        "`a` has nothing left here"
    );

    // Asking for more than there is moves everything.
    let rest = claim.split_oldest(5);
    assert_eq!(claimed_seconds(&rest), [10]);
    assert!(claimed_seconds(&claim).is_empty());
    drop((part, next, rest, claim));
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
    let first = claim.split_oldest(1);
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
    let first = claim.split_oldest(1);
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
    claim.split_oldest(1).discard("too large");
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
fn an_undelivered_untimestamped_reference_is_owed_once_its_report_began() {
    let (store, _) = store(8, 4);
    let (a, b) = (key(1, 1), key(1, 2));
    store.lock().reset_untimed(&a, 1, 10);
    store.lock().reset_untimed(&b, 1, 10);
    let claim_of = |entries: &[(&CovSubscriptionKey, u64, Option<Instant>)]| {
        let mut claim = TimedClaim::new(store.clone());
        for &(key, generation, owed) in entries {
            claim.add_untimed(key.clone(), generation, owed);
        }
        claim
    };
    // A report none of which went out owes nothing: like any lost
    // notification, the reference's next fanout reports it.
    drop(claim_of(&[(&a, 1, None)]));
    assert_eq!(store.lock().take_owed(&a, 1), None);
    // A part deferred behind a delivered one owes its references.
    let start = Instant::now();
    let mut claim = claim_of(&[(&a, 1, None), (&b, 1, None)]);
    let deferred = claim.split_untimed(&std::collections::HashSet::from([b.clone()]));
    claim.commit();
    drop(deferred.owing());
    assert_eq!(store.lock().take_owed(&a, 1), None, "delivered");
    let since = store.lock().take_owed(&b, 1).expect("owed");
    assert!(since >= start);
    assert_eq!(store.lock().take_owed(&b, 1), None, "taking settles it");
    // Once owed, a reference stays owed from when it first was until a part
    // carrying it is delivered, whichever report takes it.
    drop(claim_of(&[(&b, 1, Some(since))]));
    assert_eq!(store.lock().take_owed(&b, 1), Some(since));
    // Values that fit no notification are given up, not owed.
    let mut claim = claim_of(&[(&b, 1, Some(since))]);
    claim.forgo_untimed();
    drop(claim.owing());
    assert_eq!(store.lock().take_owed(&b, 1), None);
    // A renewed or cancelled reference owes nothing.
    let claim = claim_of(&[(&a, 1, None), (&b, 1, Some(since))]);
    store.lock().reset_untimed(&b, 2, 10);
    store.lock().remove(&a);
    drop(claim.owing());
    assert_eq!(store.lock().take_owed(&b, 2), None);
    assert_eq!(store.lock().held(), (1, 0), "only the renewed reference");
}

#[tokio::test(start_paused = true)]
async fn an_owed_reference_makes_its_context_due_like_a_pending_change() {
    let (mut h, _) = histories(8, 4);
    let k = key(1, 1);
    h.reset_untimed(&k, 1, 10);
    assert_eq!(h.take_due(Instant::now()), (Vec::new(), None));
    let start = Instant::now();
    h.owe(&k, 1, start);
    let delay = Duration::from_secs(10);
    assert_eq!(
        h.take_due(Instant::now()),
        (Vec::new(), Some(start + delay))
    );
    tokio::time::advance(delay).await;
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    // Blocked again: a hold-off moves the next attempt, and re-enabled
    // communication ends the wait.
    let until = Instant::now() + Duration::from_secs(3);
    h.hold_until(&context(1), until);
    assert_eq!(h.take_due(Instant::now()), (Vec::new(), Some(until)));
    h.rearm();
    assert_eq!(h.take_due(Instant::now()).0, std::slice::from_ref(&k));
    // A later mark keeps the earlier one, and taking the mark settles it.
    h.owe(&k, 1, Instant::now());
    assert_eq!(h.take_owed(&k, 1), Some(start));
    assert_eq!(h.take_due(Instant::now()), (Vec::new(), None));
    assert_eq!(h.held(), (1, 0), "a settled reference holds no wait");
    h.owe(&k, 1, start);
    h.remove(&k);
    assert_eq!(
        h.held(),
        (0, 0),
        "removal takes the mark and the wait along"
    );
}
