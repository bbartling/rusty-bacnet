//! A server dropped without `stop()` in async code lets its object database
//! go on Tokio's blocking pool (#1409): a class whose save storage still
//! holds no longer parks the runtime's thread while it drops.

use super::*;
use std::sync::mpsc as std_mpsc;
use std::thread::ThreadId;

/// Storage for one class that reports the thread it is dropped on. The
/// class's writer drops it last, once the class's own drop, which waits for
/// its saves, is over.
struct Reporting {
    storage: Arc<ClassStorage>,
    dropped: std_mpsc::Sender<ThreadId>,
}

impl NotificationClassPersistence for Reporting {
    fn load(&self, _class: ObjectIdentifier) -> Result<Option<NotificationClassSnapshot>, Error> {
        Ok(self.storage.load_saved())
    }

    fn save(
        &self,
        _class: ObjectIdentifier,
        snapshot: &NotificationClassSnapshot,
    ) -> Result<(), Error> {
        self.storage.store(snapshot)
    }
}

impl Drop for Reporting {
    fn drop(&mut self) {
        let _ = self.dropped.send(std::thread::current().id());
    }
}

/// The current-thread runtime has one thread, the test's own.
#[tokio::test]
async fn a_server_dropped_without_stop_lets_its_database_go_off_the_runtime() {
    let storage = holding(&[destination(1)]);
    let (dropped, dropped_on) = std_mpsc::channel();
    let persistence = Arc::new(Reporting {
        storage: Arc::clone(&storage),
        dropped,
    });
    let class = NotificationClass::with_persistence(
        1,
        "NC-1",
        persistence as Arc<dyn NotificationClassPersistence>,
    )
    .unwrap();
    let (transport, inbound) = TestTransport::inbound(4);
    let mut db = ObjectDatabase::new();
    let device = DeviceObject::new(DeviceConfig {
        instance: 100,
        ..DeviceConfig::default()
    });
    db.add(Box::new(device.unwrap())).unwrap();
    db.add(Box::new(class)).unwrap();
    let server = BACnetServer::generic_builder()
        .transport(transport)
        .database(db)
        .enable_event_enrollment(false)
        .build()
        .await
        .unwrap();
    // A staged save that storage holds: the class's drop waits for it, and
    // then puts storage back to the list the class serves.
    let (started, go) = storage.hold();
    let request = write_property(1, &[destination(11)]);
    send(&inbound, ConfirmedServiceChoice::WRITE_PROPERTY, request).await;
    save_started(started).await;
    // Should dropping the server hold the runtime's thread until storage
    // lets the save go, nothing would. A watchdog then lets it go, so the
    // test fails instead of hanging.
    let (progress, progressed) = std_mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        let stalled = progressed.recv_timeout(WAIT).is_err();
        drop(go);
        stalled
    });
    drop(server);
    // A task spawned now runs only if the runtime's thread is free.
    tokio::spawn(async move {
        let _ = progress.send(());
    })
    .await
    .unwrap();
    let stalled = tokio::task::spawn_blocking(move || watchdog.join().unwrap())
        .await
        .unwrap();
    assert!(!stalled, "dropping the server held the runtime's thread");
    // The database went on another thread once storage let the save go, and
    // the class put storage back to the list it served as it went (#1363).
    let thread = tokio::task::spawn_blocking(move || dropped_on.recv_timeout(WAIT))
        .await
        .unwrap()
        .expect("the database was dropped");
    assert_ne!(thread, std::thread::current().id());
    assert_eq!(storage.load_saved(), Some(snapshot(&[destination(1)])));
}
