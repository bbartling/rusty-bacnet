//! Saving object state off the object database lock (#1270).
//!
//! The Audit Log and the Notification Forwarder keep state in storage the
//! application provides ([`AuditLogPersistence`] and
//! [`NotificationForwarderPersistence`]). A storage call can be slow, since
//! the file backends write, synchronize and rename, so neither object makes
//! one while its caller holds the database's write guard. Both follow the
//! pattern this module provides.
//!
//! - Under the guard, the object copies the state to keep and queues the copy
//!   on its save writer. The writer's own thread makes the storage calls, one
//!   at a time and in the order they were queued.
//! - A save whose outcome decides a request is *staged*. The object sets the
//!   state the request would leave aside and keeps serving the old one. The
//!   server drops the guard and awaits the save's [`SaveWait`]; then, holding
//!   the guard again, it runs the request as usual, and the object takes the
//!   saved state, or refuses the request if the save failed. So a forwarder
//!   list write that cannot be saved is refused and leaves the old list, and an
//!   Audit notification is stored, and a confirmed one acknowledged, only once
//!   its commit is durable.
//! - A save no request waits for, such as a forwarder's lapse and minute
//!   saves, coalesces: a queued save the thread has not started is replaced by
//!   the newer one, so a burst costs one save of the latest state.
//!
//! A caller that holds the guard and cannot drop it, such as application code
//! writing through the database, gets the same outcome: the object queues the
//! save and waits for it where it is.
//!
//! # Adding an object
//!
//! Any other object that keeps a written state in storage, such as a
//! Notification Class keeping its Recipient_List (#1315), reuses this module
//! instead of saving under the guard:
//!
//! 1. Own a `SaveWriter` over a snapshot of the state to keep. Queue a save
//!    that decides a request with `SaveWriter::submit`, and one nobody waits
//!    for with `SaveWriter::submit_coalescing`.
//! 2. Implement [`DurableWrites`] for the object and return it from
//!    `BACnetObject::durable_writes_internal`.
//! 3. Add the object type to `may_save` in the server's `durable_writes`
//!    module. The server stages only the types listed there; any other
//!    type's writes save in place.
//! 4. Have a file backend call `sync_parent_dir` after its rename.
//!
//! The Notification Forwarder's `saving` module is the worked example: a
//! list write stages, and the operation task's saves coalesce.
//!
//! [`AuditLogPersistence`]: crate::audit::AuditLogPersistence
//! [`NotificationForwarderPersistence`]: crate::notification_forwarder::NotificationForwarderPersistence

use std::collections::VecDeque;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;

use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

/// How long a staged write whose save has run may wait for its request.
/// Past it the request is taken to be gone, and the object drops the staged
/// state at the next stage or operation task call.
#[cfg(not(test))]
pub(crate) const STAGED_WRITE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10);
/// Short in tests, so one can watch a forgotten staged write go.
#[cfg(test)]
pub(crate) const STAGED_WRITE_LIFETIME: std::time::Duration = std::time::Duration::from_millis(300);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Something that happens once, which any number of threads and tasks can
/// wait for.
#[derive(Default)]
pub(crate) struct Event {
    state: Mutex<EventState>,
    happened: Condvar,
}

#[derive(Default)]
struct EventState {
    done: bool,
    wakers: Vec<Waker>,
}

impl Event {
    /// Mark the event as happened and wake every waiter.
    pub(crate) fn set(&self) {
        let wakers = {
            let mut state = lock(&self.state);
            state.done = true;
            std::mem::take(&mut state.wakers)
        };
        self.happened.notify_all();
        for waker in wakers {
            waker.wake();
        }
    }

    pub(crate) fn is_set(&self) -> bool {
        lock(&self.state).done
    }

    fn wait_blocking(&self) {
        let mut state = lock(&self.state);
        while !state.done {
            state = self
                .happened
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// A future that resolves once a save has run, or once a staged write that
/// held an object has gone, whichever it was handed out for.
///
/// It holds no lock and borrows nothing, so it can be awaited after the
/// database guard is dropped.
#[must_use = "a SaveWait does nothing unless awaited"]
#[derive(Clone)]
pub struct SaveWait {
    event: Arc<Event>,
}

impl SaveWait {
    pub(crate) fn new(event: Arc<Event>) -> Self {
        Self { event }
    }

    /// Whether the wait is already over.
    pub fn is_ready(&self) -> bool {
        self.event.is_set()
    }
}

impl std::fmt::Debug for SaveWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaveWait")
            .field("ready", &self.is_ready())
            .finish()
    }
}

impl Future for SaveWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = lock(&self.event.state);
        if state.done {
            return Poll::Ready(());
        }
        if !state.wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
            state.wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

/// The outcome of one queued save, filled in by the writer's thread.
#[derive(Clone, Default)]
pub(crate) struct SaveTicket {
    slot: Arc<TicketSlot>,
}

#[derive(Default)]
struct TicketSlot {
    outcome: Mutex<Outcome>,
    done: Arc<Event>,
}

#[derive(Default)]
enum Outcome {
    #[default]
    Pending,
    Done(Result<(), Error>),
    /// Someone took the result; whether the save succeeded.
    Taken(bool),
}

impl SaveTicket {
    fn complete(&self, result: Result<(), Error>) {
        *lock(&self.slot.outcome) = Outcome::Done(result);
        self.slot.done.set();
    }

    /// Whether the save has run.
    pub(crate) fn is_done(&self) -> bool {
        self.slot.done.is_set()
    }

    /// A future that resolves once the save has run.
    pub(crate) fn wait(&self) -> SaveWait {
        SaveWait::new(Arc::clone(&self.slot.done))
    }

    /// Whether the save succeeded, once it has run.
    pub(crate) fn succeeded(&self) -> Option<bool> {
        match &*lock(&self.slot.outcome) {
            Outcome::Pending => None,
            Outcome::Done(result) => Some(result.is_ok()),
            Outcome::Taken(ok) => Some(*ok),
        }
    }

    /// Wait for the save, blocking the thread if it has not run yet, and
    /// take its result. The result goes to one taker; a later call gets an
    /// error that says so.
    pub(crate) fn take_outcome(&self) -> Result<(), Error> {
        self.slot.done.wait_blocking();
        let mut outcome = lock(&self.slot.outcome);
        match std::mem::take(&mut *outcome) {
            Outcome::Done(result) => {
                *outcome = Outcome::Taken(result.is_ok());
                result
            }
            Outcome::Taken(ok) => {
                *outcome = Outcome::Taken(ok);
                if ok {
                    Ok(())
                } else {
                    Err(Error::Encoding(
                        "save failed; its error was reported".into(),
                    ))
                }
            }
            Outcome::Pending => unreachable!("the event is set only after the outcome"),
        }
    }
}

type SaveFn<S> = dyn Fn(&S) -> Result<(), Error> + Send + Sync;
type DoneFn<S> = dyn Fn(&S, &Result<(), Error>) + Send + Sync;

/// Runs one object's storage calls on a thread of its own, one at a time, in
/// the order they were queued. See the [module documentation](self).
///
/// The thread starts with the first save and ends when the writer is
/// dropped. Dropping the writer waits for the saves already queued, so state
/// saved just before an object goes away is in storage when a new object
/// loads it.
pub(crate) struct SaveWriter<S: Send + 'static> {
    shared: Arc<Shared<S>>,
    thread: Option<JoinHandle<()>>,
    name: String,
}

struct Shared<S> {
    queue: Mutex<Queue<S>>,
    /// The thread has a job to run, or the writer is closing.
    work: Condvar,
    /// The queue has emptied and no job is running.
    idle: Condvar,
    save: Box<SaveFn<S>>,
    done: Box<DoneFn<S>>,
}

struct Queue<S> {
    jobs: VecDeque<Job<S>>,
    running: bool,
    closed: bool,
}

struct Job<S> {
    snapshot: S,
    ticket: Option<SaveTicket>,
}

impl<S: Send + 'static> SaveWriter<S> {
    /// A writer whose thread, named `name`, saves each snapshot with `save`
    /// and then reports the result to `done`.
    pub(crate) fn new(
        name: String,
        save: impl Fn(&S) -> Result<(), Error> + Send + Sync + 'static,
        done: impl Fn(&S, &Result<(), Error>) + Send + Sync + 'static,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                queue: Mutex::new(Queue {
                    jobs: VecDeque::new(),
                    running: false,
                    closed: false,
                }),
                work: Condvar::new(),
                idle: Condvar::new(),
                save: Box::new(save),
                done: Box::new(done),
            }),
            thread: None,
            name,
        }
    }

    /// Queue a save whose outcome the caller wants.
    pub(crate) fn submit(&mut self, snapshot: S) -> SaveTicket {
        let ticket = SaveTicket::default();
        self.enqueue(Job {
            snapshot,
            ticket: Some(ticket.clone()),
        });
        ticket
    }

    /// Queue a save nobody waits for. A save of this kind still queued and
    /// not started is replaced, so only the latest state is saved.
    pub(crate) fn submit_coalescing(&mut self, snapshot: S) {
        {
            let mut queue = lock(&self.shared.queue);
            if let Some(last) = queue.jobs.back_mut().filter(|job| job.ticket.is_none()) {
                last.snapshot = snapshot;
                return;
            }
        }
        self.enqueue(Job {
            snapshot,
            ticket: None,
        });
    }

    /// Block until every queued save has run.
    pub(crate) fn wait_idle(&self) {
        let mut queue = lock(&self.shared.queue);
        while queue.running || !queue.jobs.is_empty() {
            queue = self
                .shared
                .idle
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn enqueue(&mut self, job: Job<S>) {
        if self.thread.is_none() {
            let shared = Arc::clone(&self.shared);
            match std::thread::Builder::new()
                .name(self.name.clone())
                .spawn(move || run(&shared))
            {
                Ok(handle) => self.thread = Some(handle),
                Err(error) => {
                    // Without a thread the save runs here, as it did before
                    // saves left the caller's thread.
                    tracing::warn!(%error, writer = %self.name, "Could not start a save thread");
                    run_job(&self.shared, job);
                    return;
                }
            }
        }
        lock(&self.shared.queue).jobs.push_back(job);
        self.shared.work.notify_one();
    }
}

impl<S: Send + 'static> Drop for SaveWriter<S> {
    fn drop(&mut self) {
        lock(&self.shared.queue).closed = true;
        self.shared.work.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run<S>(shared: &Shared<S>) {
    loop {
        let job = {
            let mut queue = lock(&shared.queue);
            loop {
                if let Some(job) = queue.jobs.pop_front() {
                    queue.running = true;
                    break job;
                }
                if queue.closed {
                    return;
                }
                queue = shared
                    .work
                    .wait(queue)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        run_job(shared, job);
        let mut queue = lock(&shared.queue);
        queue.running = false;
        if queue.jobs.is_empty() {
            shared.idle.notify_all();
        }
    }
}

/// Make one storage call. A storage implementation that panics fails the save
/// instead of ending the thread, so every ticket still completes. The
/// snapshot is dropped before the ticket completes, so a caller that shares
/// it through an `Arc` holds the only reference once the save has run.
fn run_job<S>(shared: &Shared<S>, job: Job<S>) {
    let Job { snapshot, ticket } = job;
    let result = catch_unwind(AssertUnwindSafe(|| (shared.save)(&snapshot)))
        .unwrap_or_else(|_| Err(Error::Encoding("persistence panicked during a save".into())));
    let _ = catch_unwind(AssertUnwindSafe(|| (shared.done)(&snapshot, &result)));
    drop(snapshot);
    if let Some(ticket) = ticket {
        ticket.complete(result);
    }
}

/// Make a rename or a newly created file in `path`'s directory durable by
/// synchronizing the directory.
///
/// On Unix this opens the directory and calls `fsync` on it. Windows cannot
/// open a directory through `std::fs`, so there the call does nothing: NTFS
/// journals the rename, but a power loss right after it may still bring back
/// the previous file.
pub(crate) fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        std::fs::File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// What [`DurableWrites::stage_write`] gave its caller.
#[doc(hidden)]
#[derive(Debug)]
pub enum StageStep {
    /// The object queued a save of the state the write would leave, and keeps
    /// that state aside. Await the wait without the database guard, then make
    /// the write as usual: the object takes the saved state, or refuses the
    /// write if the save failed.
    Staged(SaveWait),
    /// Another request's staged write holds the object. Await the wait, then
    /// stage again.
    Busy(SaveWait),
    /// Nothing to stage: the object saves nothing for this write, or will
    /// refuse it anyway. Make the write as usual.
    Skip,
}

/// Writes whose new state an object saves before serving it, staged so the
/// save runs while the database guard is dropped (#1270).
///
/// The bundled server stages each such write it receives: it calls
/// [`stage_write`](Self::stage_write) under the guard, awaits the save after
/// dropping it, makes the write under the guard again, and in that same
/// critical section calls [`release_staged_write`](Self::release_staged_write).
/// A write made without staging still works: the object then saves in place.
#[doc(hidden)]
pub trait DurableWrites {
    /// Stage a write of `value` to `property` (at `array_index`).
    fn stage_write(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: &PropertyValue,
    ) -> StageStep;

    /// The request that staged a write is done, whether or not the write
    /// reached the object. A staged state the write never took is dropped,
    /// and storage is brought back to the state the object serves.
    fn release_staged_write(&mut self);
}

#[cfg(test)]
#[path = "durable/tests.rs"]
mod tests;
