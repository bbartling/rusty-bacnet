//! An object's save writer together with the one write staged on it (#1270).
//!
//! The Notification Forwarder and the Notification Class share this part of
//! the pattern the [module documentation](super) describes: a write staged
//! for a request keeps the state it leaves aside while its save runs, the
//! write then takes that state or the save's error, and a staged write its
//! request never makes is dropped and corrected.
//!
//! A request can vanish between its stage and its write: the server's
//! `stop()` aborts requests, and an application can drop a local write's
//! future. Its staged write then lingers, and storage may hold a state the
//! object never served. Two checks drop it once
//! [`STAGED_WRITE_LIFETIME`] has passed since
//! its save finished: the next stage of a write to the object
//! ([`busy`](StagedSaves::busy)), and the object's call from the server's
//! once-a-second operation task ([`expire`](StagedSaves::expire)), which
//! measures the lifetime on that task's monotonic clock. Either way the
//! object then saves the state it serves.
//!
//! Neither check runs once the server has stopped, so two more cover the
//! end of an object's life (#1363). The server's `stop()`, once it has
//! joined every request, drops what is still staged
//! ([`drop_forgotten`](StagedSaves::drop_forgotten)) and waits for the
//! correcting save. And an object dropped with a write still staged puts
//! storage back as it goes: `StagedSaves` keeps, beside the staged write,
//! the state the object served at its latest storage call, and its `Drop`
//! saves that state, unless the staged save failed, before the writer's own
//! drop joins the thread. An object that stages through `StagedSaves` gets
//! this without a `Drop` of its own; [`stage`](StagedSaves::stage) takes
//! the served state, and [`correct`](StagedSaves::correct) keeps it current.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use super::{Event, SaveTicket, SaveWait, SaveWriter, StageStep, STAGED_WRITE_LIFETIME};

/// A write staged for a request: the state `N` it leaves, saving on the
/// writer, and the snapshot `S` of the state the object serves meanwhile.
struct StagedWrite<S, N> {
    property: PropertyIdentifier,
    value: PropertyValue,
    /// The object's write count when staged. The write takes the staged
    /// state only if no other write came between.
    base: u64,
    next: N,
    ticket: SaveTicket,
    /// The state the object served at its latest storage call: what
    /// storage goes back to if the staged write is dropped before
    /// [`correct`](StagedSaves::correct) can ask for a fresh one, as when
    /// the object itself is dropped.
    served: S,
    /// Set when the staged write is taken or dropped, for a request that
    /// found the object busy.
    released: Arc<Event>,
    /// The operation task's monotonic time when it first found the save
    /// finished; [`StagedSaves::expire`] counts the lifetime from it.
    finished_seen_at: Option<Duration>,
}

/// One object's save writer, saving snapshots `S`, and the write staged on
/// it, which leaves the state `N`.
///
/// The object owns the state it serves, so whatever needs it comes in as a
/// closure: [`correct`](Self::correct) asks for the snapshot of the served
/// state when a dropped staged write may have left storage ahead of it, or
/// to keep the copy a staged write holds current.
pub(crate) struct StagedSaves<S: Send + 'static, N> {
    writer: SaveWriter<S>,
    staged: Option<StagedWrite<S, N>>,
    /// A staged write was dropped whose save did not fail, so storage may
    /// hold a state the object never served: the served state that write
    /// kept. [`correct`](Self::correct) saves a fresh snapshot instead; a
    /// drop saves this one.
    correction: Option<S>,
}

impl<S: Send + 'static, N> StagedSaves<S, N> {
    /// Saves through `writer`, with nothing staged.
    pub(crate) fn new(writer: SaveWriter<S>) -> Self {
        Self {
            writer,
            staged: None,
            correction: None,
        }
    }

    /// The wait for a staged write that still holds the object: one whose
    /// save is running, or finished within
    /// [`STAGED_WRITE_LIFETIME`]. An older one
    /// is dropped.
    pub(crate) fn busy(&mut self) -> Option<SaveWait> {
        self.busy_at(Instant::now())
    }

    /// [`busy`](Self::busy), judged at `now`.
    pub(crate) fn busy_at(&mut self, now: Instant) -> Option<SaveWait> {
        let staged = self.staged.as_ref()?;
        if !staged.ticket.outlived_at(now) {
            return Some(SaveWait::new(Arc::clone(&staged.released)));
        }
        self.drop_staged();
        None
    }

    /// Queue a save of `snapshot` for a write of `value` to `property` made
    /// at write count `base` that leaves `next`, and keep `next` aside until
    /// the write arrives. `served` is the state the object serves now, which
    /// storage goes back to should the staged write be dropped.
    pub(crate) fn stage(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        base: u64,
        next: N,
        snapshot: S,
        served: S,
    ) -> StageStep {
        // A correction still due lands first, should this save fail.
        if let Some(correction) = self.correction.take() {
            self.writer.submit_coalescing(correction);
        }
        let ticket = self.writer.submit(snapshot);
        let wait = ticket.wait();
        self.staged = Some(StagedWrite {
            property,
            value,
            base,
            next,
            ticket,
            served,
            released: Arc::default(),
            finished_seen_at: None,
        });
        StageStep::Staged(wait)
    }

    /// From the object's operation-task call at monotonic `now`: drop a
    /// staged write whose request is gone. The first call that finds its
    /// save finished starts the count, and a call
    /// [`STAGED_WRITE_LIFETIME`] or more after that drops it, so on the
    /// server's once-a-second task a forgotten write goes within the lifetime
    /// and one tick of its save. A save still running never expires. A clock
    /// that moved back, such as a newly bound one, starts the count again.
    pub(crate) fn expire(&mut self, now: Duration) {
        let Some(staged) = self.staged.as_mut() else {
            return;
        };
        if !staged.ticket.is_done() {
            return;
        }
        let seen = match staged.finished_seen_at {
            Some(seen) if seen <= now => seen,
            _ => *staged.finished_seen_at.insert(now),
        };
        if now - seen >= STAGED_WRITE_LIFETIME {
            self.drop_staged();
        }
    }

    /// Take the staged state for a write of `value` to `property` made at
    /// write count `base`: the state if its save succeeded, the save's error
    /// if not. `None` when no staged write matches; a staged write that does
    /// not match is dropped, since the write about to be saved supersedes it.
    pub(crate) fn claim(
        &mut self,
        property: PropertyIdentifier,
        value: &PropertyValue,
        base: u64,
    ) -> Option<Result<N, Error>> {
        let staged = self.staged.as_ref()?;
        if staged.property != property || staged.base != base || staged.value != *value {
            self.drop_staged();
            return None;
        }
        let staged = self.staged.take().expect("matched above");
        staged.released.set();
        Some(staged.ticket.take_outcome().map(|()| staged.next))
    }

    /// Save `snapshot` and wait for the outcome, for a write nobody staged.
    pub(crate) fn save_now(&mut self, snapshot: S) -> Result<(), Error> {
        self.writer.submit(snapshot).take_outcome()
    }

    /// Queue a save nobody waits for; see
    /// [`SaveWriter::submit_coalescing`].
    pub(crate) fn submit_coalescing(&mut self, snapshot: S) {
        self.writer.submit_coalescing(snapshot);
    }

    /// The request that staged a write and was given `wait` is done. A
    /// staged write another request made is left alone.
    pub(crate) fn release(&mut self, wait: &SaveWait) {
        if self
            .staged
            .as_ref()
            .is_some_and(|staged| staged.ticket.issued(wait))
        {
            self.drop_staged();
        }
    }

    /// Drop the staged write, if any, waking the requests that wait for it.
    pub(crate) fn drop_staged(&mut self) {
        let Some(staged) = self.staged.take() else {
            return;
        };
        staged.released.set();
        // Unless its save failed, storage holds, or is about to hold, a state
        // the object never served.
        if staged.ticket.succeeded() != Some(false) {
            self.correction = Some(staged.served);
        }
    }

    /// Whether a dropped staged write left a correction due, clearing it:
    /// for a caller that queues the correcting save its own way.
    pub(crate) fn take_correction(&mut self) -> bool {
        self.correction.take().is_some()
    }

    /// After a storage call, with `served` giving the state the object
    /// serves. If the call dropped a staged write, queue a save of that
    /// state at once; it lands after the dropped write's save, since saves
    /// run in order. If a write is still staged, keep the state with it
    /// instead, for a drop of the object to put back.
    pub(crate) fn correct(&mut self, served: impl FnOnce() -> S) {
        if self.take_correction() {
            self.writer.submit_coalescing(served());
        } else if let Some(staged) = self.staged.as_mut() {
            staged.served = served();
        }
    }

    /// No request is left to take or release the staged write, as once the
    /// server's `stop()` has joined its requests: drop it, queue the save of
    /// `served` that leaves due, and return a wait that ends once every save
    /// queued so far has run.
    pub(crate) fn drop_forgotten(&mut self, served: impl FnOnce() -> S) -> SaveWait {
        self.drop_staged();
        self.correct(served);
        self.writer.idle()
    }

    /// Block until every queued save has run.
    pub(crate) fn wait_idle(&self) {
        self.writer.wait_idle();
    }
}

impl<S: Send + 'static, N> Drop for StagedSaves<S, N> {
    /// The object is going away with nothing left to take a staged write.
    /// Drop it as a release would, and put storage back to the served state
    /// it kept before the writer, dropped next, joins its thread (#1363).
    fn drop(&mut self) {
        self.drop_staged();
        if let Some(served) = self.correction.take() {
            self.writer.put_back(served);
        }
    }
}
