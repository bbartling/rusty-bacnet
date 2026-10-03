//! The shared save writer (#1270).

use super::*;
use std::sync::mpsc;
use std::task::Wake;
use std::thread::ThreadId;
use std::time::Duration;

/// A storage stand-in whose saves block until the test lets each one go.
struct Gate {
    started: Mutex<mpsc::Sender<u32>>,
    release: Mutex<mpsc::Receiver<Result<(), Error>>>,
    saved: Mutex<Vec<u32>>,
    threads: Mutex<Vec<ThreadId>>,
}

struct GateHandle {
    started: mpsc::Receiver<u32>,
    release: mpsc::Sender<Result<(), Error>>,
}

fn gate() -> (Arc<Gate>, GateHandle) {
    let (started_tx, started) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    (
        Arc::new(Gate {
            started: Mutex::new(started_tx),
            release: Mutex::new(release_rx),
            saved: Mutex::default(),
            threads: Mutex::default(),
        }),
        GateHandle { started, release },
    )
}

fn writer(gate: &Arc<Gate>) -> SaveWriter<u32> {
    let saving = Arc::clone(gate);
    SaveWriter::new(
        "test-writer".into(),
        move |snapshot: &u32| {
            saving
                .threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            saving.started.lock().unwrap().send(*snapshot).unwrap();
            let result = saving.release.lock().unwrap().recv().unwrap();
            if result.is_ok() {
                saving.saved.lock().unwrap().push(*snapshot);
            }
            result
        },
        |_, _| {},
    )
}

const WAIT: Duration = Duration::from_secs(10);

#[test]
fn saves_run_in_order_on_the_writer_thread() {
    let (gate, handle) = gate();
    let mut writer = writer(&gate);
    let first = writer.submit(1);
    let second = writer.submit(2);
    assert_eq!(handle.started.recv_timeout(WAIT).unwrap(), 1);
    // The caller is free while the first save runs.
    assert!(!first.is_done());
    handle.release.send(Ok(())).unwrap();
    assert_eq!(handle.started.recv_timeout(WAIT).unwrap(), 2);
    handle
        .release
        .send(Err(Error::Encoding("disk full".into())))
        .unwrap();
    assert!(first.take_outcome().is_ok());
    assert!(second.take_outcome().is_err());
    assert_eq!(*gate.saved.lock().unwrap(), [1]);
    assert_ne!(gate.threads.lock().unwrap()[0], std::thread::current().id());
    // The result went to its one taker.
    assert_eq!(second.succeeded(), Some(false));
    assert!(second.take_outcome().is_err());
}

#[test]
fn a_burst_of_unwaited_saves_coalesces_to_the_latest() {
    let (gate, handle) = gate();
    let mut writer = writer(&gate);
    writer.submit_coalescing(1);
    assert_eq!(handle.started.recv_timeout(WAIT).unwrap(), 1);
    // While the first runs, a burst queues; each replaces the one before.
    for snapshot in 2..=9 {
        writer.submit_coalescing(snapshot);
    }
    handle.release.send(Ok(())).unwrap();
    assert_eq!(handle.started.recv_timeout(WAIT).unwrap(), 9);
    handle.release.send(Ok(())).unwrap();
    writer.wait_idle();
    assert_eq!(*gate.saved.lock().unwrap(), [1, 9]);
}

#[test]
fn a_waited_save_is_never_replaced_and_keeps_its_place() {
    let (gate, handle) = gate();
    let mut writer = writer(&gate);
    writer.submit_coalescing(1);
    assert_eq!(handle.started.recv_timeout(WAIT).unwrap(), 1);
    writer.submit_coalescing(2);
    let waited = writer.submit(3);
    writer.submit_coalescing(4);
    for _ in 0..4 {
        handle.release.send(Ok(())).unwrap();
    }
    writer.wait_idle();
    assert!(waited.take_outcome().is_ok());
    assert_eq!(*gate.saved.lock().unwrap(), [1, 2, 3, 4]);
}

#[test]
fn dropping_the_writer_waits_for_queued_saves() {
    let (gate, handle) = gate();
    let mut writer = writer(&gate);
    writer.submit_coalescing(1);
    writer.submit(2);
    for _ in 0..2 {
        handle.release.send(Ok(())).unwrap();
    }
    drop(writer);
    assert_eq!(*gate.saved.lock().unwrap(), [1, 2]);
}

#[test]
fn a_panicking_save_fails_its_ticket_and_the_writer_goes_on() {
    let mut writer = SaveWriter::new(
        "test-writer".into(),
        |snapshot: &u32| {
            assert_ne!(*snapshot, 1, "storage bug");
            Ok(())
        },
        |_, _| {},
    );
    let failed = writer.submit(1);
    let next = writer.submit(2);
    assert!(failed.take_outcome().is_err());
    assert!(next.take_outcome().is_ok());
}

#[test]
fn the_done_hook_sees_every_result() {
    let results = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&results);
    let mut writer = SaveWriter::new(
        "test-writer".into(),
        |snapshot: &u32| {
            if snapshot.is_multiple_of(2) {
                Ok(())
            } else {
                Err(Error::Encoding("odd".into()))
            }
        },
        move |snapshot, result| seen.lock().unwrap().push((*snapshot, result.is_ok())),
    );
    writer.submit(1);
    writer.submit_coalescing(2);
    writer.wait_idle();
    assert_eq!(*results.lock().unwrap(), [(1, false), (2, true)]);
}

struct Flag(std::sync::atomic::AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn a_save_wait_wakes_its_task_when_the_save_runs() {
    let (gate, handle) = gate();
    let mut writer = writer(&gate);
    let ticket = writer.submit(1);
    let mut wait = ticket.wait();
    let flag = Arc::new(Flag(Default::default()));
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    assert_eq!(handle.started.recv_timeout(WAIT).unwrap(), 1);
    handle.release.send(Ok(())).unwrap();
    writer.wait_idle();
    assert!(flag.0.load(std::sync::atomic::Ordering::SeqCst));
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    assert!(wait.is_ready());
}

#[test]
fn a_directory_sync_follows_a_rename() {
    let dir = std::env::temp_dir().join(format!("rusty-bacnet-durable-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state");
    std::fs::write(dir.join("state.tmp"), b"x").unwrap();
    std::fs::rename(dir.join("state.tmp"), &path).unwrap();
    sync_parent_dir(&path).unwrap();
    // A bare file name syncs the working directory.
    sync_parent_dir(Path::new("state")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
