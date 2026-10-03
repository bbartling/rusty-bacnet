//! Subscribed_Recipients across a restart (Clause 12.51.9).

use super::*;
use bacnet_types::enums::PropertyIdentifier as P;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Default)]
struct MemoryPersistence {
    saved: Mutex<Option<(ObjectIdentifier, Vec<BACnetEventNotificationSubscription>)>>,
    fail: AtomicBool,
}

impl MemoryPersistence {
    fn saved(&self) -> Vec<BACnetEventNotificationSubscription> {
        self.saved.lock().unwrap().clone().unwrap().1
    }
}

impl SubscribedRecipientsPersistence for MemoryPersistence {
    fn load(
        &self,
        forwarder: ObjectIdentifier,
    ) -> Result<Option<Vec<BACnetEventNotificationSubscription>>, Error> {
        Ok(self
            .saved
            .lock()
            .unwrap()
            .clone()
            .filter(|(oid, _)| *oid == forwarder)
            .map(|(_, list)| list))
    }

    fn save(
        &self,
        forwarder: ObjectIdentifier,
        subscriptions: &[BACnetEventNotificationSubscription],
    ) -> Result<(), Error> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Encoding("storage unavailable".into()));
        }
        *self.saved.lock().unwrap() = Some((forwarder, subscriptions.to_vec()));
        Ok(())
    }
}

fn write(nf: &mut NotificationForwarderObject, list: &[BACnetEventNotificationSubscription]) {
    nf.write_property(
        P::SUBSCRIBED_RECIPIENTS,
        None,
        framed_subscriptions(list),
        None,
    )
    .unwrap();
}

fn minutes(nf: &NotificationForwarderObject) -> Vec<u32> {
    nf.subscriptions()
        .iter()
        .map(|entry| entry.time_remaining)
        .collect()
}

#[test]
fn subscribed_recipients_restart_lands_between_the_time_left_and_the_last_subscription() {
    let storage = Arc::new(MemoryPersistence::default());
    let (clock, set) = manual_clock();
    let mut before = NotificationForwarderObject::with_persistence(
        1,
        "NF",
        Arc::clone(&storage) as Arc<dyn SubscribedRecipientsPersistence>,
    )
    .unwrap();
    before.bind_monotonic_clock_internal(Some(Arc::clone(&clock)));
    let a = |minutes| subscription(device(7), 1, minutes);
    let b = |minutes| subscription(device(8), 1, minutes);
    let c = |minutes| subscription(address(0, &[9]), 2, minutes);

    write(&mut before, &[a(10), b(30)]);
    assert_eq!(storage.saved(), [a(10), b(30)]);
    // Four minutes on, a third entry is added; the two held ones keep their
    // deadlines, and each saved entry carries the minutes it has left.
    set(4 * MINUTE);
    write(&mut before, &[a(6), b(26), c(20)]);
    assert_eq!(storage.saved(), [a(6), b(26), c(20)]);
    // Three more minutes pass with no change, then the device stops.
    set(7 * MINUTE);
    let at_stop = minutes(&before);
    assert_eq!(at_stop, [3, 23, 17]);
    drop(before);

    let mut after = NotificationForwarderObject::with_persistence(
        1,
        "NF",
        Arc::clone(&storage) as Arc<dyn SubscribedRecipientsPersistence>,
    )
    .unwrap();
    after.bind_monotonic_clock_internal(Some(clock));
    let restored = minutes(&after);
    let last_subscribed = [10, 30, 20];
    for ((restored, stopped), subscribed) in restored.iter().zip(at_stop).zip(last_subscribed) {
        assert!(
            (stopped..=subscribed).contains(restored),
            "{restored} minutes must lie between {stopped} and {subscribed}"
        );
    }
    assert_eq!(restored, [6, 26, 20]);

    // An entry that lapses after the restart leaves the saved copy too.
    set(13 * MINUTE);
    assert!(after.advance_monotonic_time_internal(13 * MINUTE));
    assert_eq!(storage.saved(), [b(20), c(14)]);
}

#[test]
fn subscribed_recipients_write_that_cannot_be_saved_is_refused() {
    let storage = Arc::new(MemoryPersistence::default());
    let mut nf = NotificationForwarderObject::with_persistence(
        1,
        "NF",
        Arc::clone(&storage) as Arc<dyn SubscribedRecipientsPersistence>,
    )
    .unwrap();
    write(&mut nf, &[subscription(device(7), 1, 10)]);
    storage.fail.store(true, Ordering::SeqCst);
    assert_refused(
        nf.write_property(
            P::SUBSCRIBED_RECIPIENTS,
            None,
            framed_subscriptions(&[subscription(device(8), 1, 10)]),
            None,
        ),
        ErrorClass::DEVICE,
        ErrorCode::OPERATIONAL_PROBLEM,
    );
    assert_eq!(nf.subscriptions(), [subscription(device(7), 1, 10)]);
    assert_eq!(storage.saved(), [subscription(device(7), 1, 10)]);
}

#[test]
fn subscribed_recipients_saved_out_of_range_refuses_the_forwarder() {
    let storage = Arc::new(MemoryPersistence::default());
    storage
        .save(
            ObjectIdentifier::new(ObjectType::NOTIFICATION_FORWARDER, 1).unwrap(),
            &[subscription(device(7), 1, 0)],
        )
        .unwrap();
    assert!(NotificationForwarderObject::with_persistence(1, "NF", storage).is_err());
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_file() -> PathBuf {
    let serial = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!(
            "rusty-bacnet-forwarder-{}-{serial}",
            std::process::id()
        ))
        .join("subscribed")
}

#[test]
fn file_persistence_round_trips_and_refuses_another_objects_file() {
    let path = temp_file();
    let storage = FileSubscribedRecipientsPersistence::new(&path).unwrap();
    let forwarder = ObjectIdentifier::new(ObjectType::NOTIFICATION_FORWARDER, 1).unwrap();
    assert_eq!(storage.load(forwarder).unwrap(), None);
    let list = [
        subscription(device(7), 1, 10),
        subscription(address(5, &[1, 2, 3, 4, 0xBA, 0xC0]), 9, 1440),
    ];
    storage.save(forwarder, &list).unwrap();
    assert_eq!(storage.load(forwarder).unwrap().unwrap(), list);
    storage.save(forwarder, &list[1..]).unwrap();
    assert_eq!(storage.load(forwarder).unwrap().unwrap(), list[1..]);

    let other = ObjectIdentifier::new(ObjectType::NOTIFICATION_FORWARDER, 2).unwrap();
    assert!(storage.load(other).is_err());
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 1);
    std::fs::write(&path, &bytes).unwrap();
    assert!(storage.load(forwarder).is_err());
    std::fs::write(&path, b"not a forwarder file").unwrap();
    assert!(storage.load(forwarder).is_err());

    assert!(FileSubscribedRecipientsPersistence::new("").is_err());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn file_persistence_keeps_a_forwarder_list_across_a_rebuild() {
    let path = temp_file();
    let storage = || {
        Arc::new(FileSubscribedRecipientsPersistence::new(&path).unwrap())
            as Arc<dyn SubscribedRecipientsPersistence>
    };
    let mut nf = NotificationForwarderObject::with_persistence(4, "NF", storage()).unwrap();
    write(&mut nf, &[subscription(device(7), 3, 15)]);
    drop(nf);
    let rebuilt = NotificationForwarderObject::with_persistence(4, "NF", storage()).unwrap();
    assert_eq!(rebuilt.subscriptions(), [subscription(device(7), 3, 15)]);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
