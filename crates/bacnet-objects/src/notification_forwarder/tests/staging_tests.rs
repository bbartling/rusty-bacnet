//! Saves that run off the database lock (#1270): staged writes, and the
//! operation task's coalesced saves.

use super::storage::{block_on, persistent, MemoryPersistence, WAIT};
use super::*;
use crate::durable::{DurableWrites, StageStep};
use bacnet_types::enums::PropertyIdentifier as P;
use std::sync::atomic::Ordering;

fn staged(step: StageStep) -> crate::durable::SaveWait {
    match step {
        StageStep::Staged(wait) => wait,
        other => panic!("expected a staged write, got {other:?}"),
    }
}

fn busy(step: StageStep) -> crate::durable::SaveWait {
    match step {
        StageStep::Busy(wait) => wait,
        other => panic!("expected a busy forwarder, got {other:?}"),
    }
}

fn write(
    nf: &mut NotificationForwarderObject,
    list: &[BACnetEventNotificationSubscription],
) -> Result<(), Error> {
    nf.write_property(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        framed_subscriptions(list),
        None,
    )
}

#[test]
fn a_staged_write_saves_while_the_forwarder_serves_the_old_list() {
    let storage = Arc::new(MemoryPersistence::default());
    let mut nf = persistent(&storage);
    let old = [subscription(device(7), 1, 10)];
    write(&mut nf, &old).unwrap();
    let held = storage.hold();
    let new = [subscription(device(8), 2, 20)];
    let wait = staged(nf.stage_write(P::SUBSCRIBED_RECIPIENTS, None, &framed_subscriptions(&new)));

    // The save runs on the writer thread and is held there. The forwarder,
    // and so the database guard that would hold it, is free meanwhile: it
    // answers reads, and serves the old list.
    let saving = held.started.recv_timeout(WAIT).unwrap();
    assert_eq!(saving.subscribed_recipients, new);
    assert!(!wait.is_ready());
    assert_eq!(
        nf.read_property(P::SUBSCRIBED_RECIPIENTS, None).unwrap(),
        framed_subscriptions(&old)
    );
    held.go.send(()).unwrap();
    block_on(wait);

    // The write takes the saved list without saving again.
    write(&mut nf, &new).unwrap();
    nf.release_staged_write();
    assert_eq!(nf.subscriptions(), new);
    assert_eq!(storage.saved(), new);
    assert_eq!(storage.saves(), 2);
}

#[test]
fn a_staged_write_whose_save_fails_is_refused_and_the_old_list_stays() {
    let storage = Arc::new(MemoryPersistence::default());
    let mut nf = persistent(&storage);
    let counters = nf.save_counters();
    let old = [subscription(device(7), 1, 10)];
    write(&mut nf, &old).unwrap();
    storage.fail.store(true, Ordering::SeqCst);
    let new = [subscription(device(8), 2, 20)];
    block_on(staged(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&new),
    )));
    assert_refused(
        write(&mut nf, &new),
        ErrorClass::DEVICE,
        ErrorCode::OPERATIONAL_PROBLEM,
    );
    nf.release_staged_write();
    assert_eq!(nf.subscriptions(), old);
    assert_eq!(storage.saved(), old);
    assert_eq!(counters.failed_saves(), 1);
}

#[test]
fn a_second_write_waits_until_the_first_has_landed() {
    let storage = Arc::new(MemoryPersistence::default());
    let mut nf = persistent(&storage);
    let first = [subscription(device(7), 1, 10)];
    let second = [subscription(device(8), 1, 10)];
    let wait = staged(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&first),
    ));
    let queued = busy(nf.stage_write(
        P::RECIPIENT_LIST,
        None,
        &framed_destinations(&[destination(device(3), 1, false)]),
    ));
    block_on(wait);
    // Saved, but not yet taken: the second still waits.
    assert!(!queued.is_ready());
    write(&mut nf, &first).unwrap();
    nf.release_staged_write();
    block_on(queued);
    block_on(staged(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&second),
    )));
    write(&mut nf, &second).unwrap();
    nf.release_staged_write();
    assert_eq!(nf.subscriptions(), second);
    assert_eq!(storage.saved(), second);
}

#[test]
fn a_staged_write_its_request_never_made_leaves_storage_with_the_served_list() {
    let storage = Arc::new(MemoryPersistence::default());
    let (clock, set) = manual_clock();
    let mut nf = persistent(&storage);
    nf.bind_monotonic_clock_internal(Some(clock));
    let served = [subscription(device(7), 1, 10)];
    write(&mut nf, &served).unwrap();
    let never = [subscription(device(9), 1, 10)];
    block_on(staged(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&never),
    )));
    // The request failed before its write; storage holds the staged list.
    nf.release_staged_write();
    assert_eq!(storage.saved(), never);
    // The next operation task call saves the served list, without waiting
    // for the minute.
    set(Duration::from_secs(1));
    nf.advance_monotonic_time_internal(Duration::from_secs(1));
    nf.wait_for_saves();
    assert_eq!(storage.saved(), served);
    assert_eq!(nf.subscriptions(), served);
}

#[test]
fn a_write_nobody_staged_supersedes_a_staged_one() {
    let storage = Arc::new(MemoryPersistence::default());
    let mut nf = persistent(&storage);
    let staged_list = [subscription(device(7), 1, 10)];
    let direct = [subscription(device(8), 1, 10)];
    block_on(staged(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&staged_list),
    )));
    // A write made without staging, by application code holding the guard,
    // saves in place and drops the staged list.
    write(&mut nf, &direct).unwrap();
    assert_eq!(storage.saved(), direct);
    // The staged write's request arrives late: it saves again, and wins.
    write(&mut nf, &staged_list).unwrap();
    nf.release_staged_write();
    assert_eq!(nf.subscriptions(), staged_list);
    assert_eq!(storage.saved(), staged_list);
}

#[test]
fn a_forgotten_staged_write_frees_the_forwarder() {
    let storage = Arc::new(MemoryPersistence::default());
    let mut nf = persistent(&storage);
    let list = [subscription(device(7), 1, 10)];
    block_on(staged(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&list),
    )));
    let waiting =
        busy(nf.stage_write(P::SUBSCRIBED_RECIPIENTS, None, &framed_subscriptions(&list)));
    // Its request never comes back. Once the staged write's lifetime is
    // over, the operation task drops it and the waiting request goes on.
    std::thread::sleep(Duration::from_millis(400));
    nf.advance_monotonic_time_internal(Duration::ZERO);
    block_on(waiting);
    block_on(staged(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&list),
    )));
    write(&mut nf, &list).unwrap();
    nf.release_staged_write();
    assert_eq!(nf.subscriptions(), list);
}

#[test]
fn staging_skips_writes_the_forwarder_does_not_save_or_will_refuse() {
    let storage = Arc::new(MemoryPersistence::default());
    let mut nf = persistent(&storage);
    let list = framed_subscriptions(&[subscription(device(7), 1, 10)]);
    let skipped = |step| matches!(step, StageStep::Skip);
    assert!(skipped(nf.stage_write(
        P::PROCESS_IDENTIFIER_FILTER,
        None,
        &PropertyValue::Null
    )));
    assert!(skipped(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        Some(1),
        &list
    )));
    // A Time Remaining of 0 is refused by the write itself.
    assert!(skipped(nf.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &framed_subscriptions(&[subscription(device(7), 1, 0)]),
    )));
    let mut in_memory = NotificationForwarderObject::new(2, "NF-2").unwrap();
    assert!(skipped(in_memory.stage_write(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        &list
    )));
    nf.wait_for_saves();
    assert_eq!(storage.saves(), 0);
}

#[test]
fn operation_task_saves_coalesce_and_never_hold_the_forwarder() {
    let storage = Arc::new(MemoryPersistence::default());
    let (clock, set) = manual_clock();
    let mut nf = persistent(&storage);
    nf.bind_monotonic_clock_internal(Some(clock));
    let entries: Vec<_> = (1..=6)
        .map(|minutes| subscription(device(minutes), 1, minutes))
        .collect();
    write(&mut nf, &entries).unwrap();
    let held = storage.hold();
    // The entry with one minute lapses: its save starts and is held.
    set(MINUTE);
    assert!(nf.advance_monotonic_time_internal(MINUTE));
    held.started.recv_timeout(WAIT).unwrap();
    // While it is held, four more entries lapse, one a minute. Each call
    // returns at once, and each queued save replaces the one before.
    for minute in 2..=5 {
        let at = MINUTE * minute;
        set(at);
        assert!(nf.advance_monotonic_time_internal(at));
        assert_eq!(nf.subscriptions().len(), 6 - minute as usize);
    }
    drop(held.go);
    nf.wait_for_saves();
    // The write, the held save, and one save of the latest list.
    assert_eq!(storage.saves(), 3);
    assert_eq!(storage.saved(), [subscription(device(6), 1, 1)]);
}

#[test]
fn an_operation_task_save_returns_while_storage_is_held() {
    let storage = Arc::new(MemoryPersistence::default());
    let (clock, set) = manual_clock();
    let mut nf = persistent(&storage);
    nf.bind_monotonic_clock_internal(Some(clock));
    write(
        &mut nf,
        &[subscription(device(1), 1, 1), subscription(device(2), 1, 6)],
    )
    .unwrap();
    let held = storage.hold();
    set(MINUTE);
    // The lapse queues a save; the call returns while storage still holds
    // it, so the operation task never keeps the database guard for a save.
    let (returned_tx, returned) = std::sync::mpsc::channel();
    let returned_in_time = std::thread::scope(|scope| {
        scope.spawn(|| {
            nf.advance_monotonic_time_internal(MINUTE);
            returned_tx.send(()).unwrap();
        });
        held.started
            .recv_timeout(WAIT)
            .expect("the lapse save started");
        let in_time = returned.recv_timeout(Duration::from_millis(500)).is_ok();
        drop(held.go);
        in_time
    });
    assert!(
        returned_in_time,
        "the operation task call waited for the save"
    );
    nf.wait_for_saves();
    assert_eq!(storage.saved(), [subscription(device(2), 1, 5)]);
}
