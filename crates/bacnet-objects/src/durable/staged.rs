//! An object's save writer together with the one write staged on it (#1270).
//!
//! The Notification Forwarder and the Notification Class share this part of
//! the pattern the [module documentation](super) describes: a write staged
//! for a request keeps the state it leaves aside while its save runs, the
//! write then takes that state or the save's error, and a staged write its
//! request never makes is dropped and corrected.

use std::sync::Arc;
use std::time::Instant;

use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use super::{Event, SaveTicket, SaveWait, SaveWriter, StageStep};

/// A write staged for a request: the state `N` it leaves, saving on the
/// writer.
struct StagedWrite<N> {
    property: PropertyIdentifier,
    value: PropertyValue,
    /// The object's write count when staged. The write takes the staged
    /// state only if no other write came between.
    base: u64,
    next: N,
    ticket: SaveTicket,
    /// Set when the staged write is taken or dropped, for a request that
    /// found the object busy.
    released: Arc<Event>,
}

/// One object's save writer, saving snapshots `S`, and the write staged on
/// it, which leaves the state `N`.
///
/// The object owns the state it serves, so whatever needs it comes in as a
/// closure: [`correct`](Self::correct) asks for the snapshot of the served
/// state when a dropped staged write may have left storage ahead of it.
pub(crate) struct StagedSaves<S: Send + 'static, N> {
    writer: SaveWriter<S>,
    staged: Option<StagedWrite<N>>,
    /// A staged write was dropped whose save did not fail, so storage may
    /// hold a state the object never served; [`correct`](Self::correct)
    /// saves the served one.
    correction_due: bool,
}

impl<S: Send + 'static, N> StagedSaves<S, N> {
    /// Saves through `writer`, with nothing staged.
    pub(crate) fn new(writer: SaveWriter<S>) -> Self {
        Self {
            writer,
            staged: None,
            correction_due: false,
        }
    }

    /// The wait for a staged write that still holds the object: one whose
    /// save is running, or finished within
    /// [`STAGED_WRITE_LIFETIME`](super::STAGED_WRITE_LIFETIME). An older one
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
    /// the write arrives.
    pub(crate) fn stage(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        base: u64,
        next: N,
        snapshot: S,
    ) -> StageStep {
        let ticket = self.writer.submit(snapshot);
        let wait = ticket.wait();
        self.staged = Some(StagedWrite {
            property,
            value,
            base,
            next,
            ticket,
            released: Arc::default(),
        });
        StageStep::Staged(wait)
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
            self.correction_due = true;
        }
    }

    /// Whether a dropped staged write left a correction due, clearing it:
    /// for a caller that queues the correcting save its own way.
    pub(crate) fn take_correction(&mut self) -> bool {
        std::mem::take(&mut self.correction_due)
    }

    /// After a staged write was dropped, queue a save of `served`, the state
    /// the object serves, at once. It lands after the dropped write's save,
    /// since saves run in order.
    pub(crate) fn correct(&mut self, served: impl FnOnce() -> S) {
        if self.take_correction() {
            self.writer.submit_coalescing(served());
        }
    }

    /// Block until every queued save has run.
    pub(crate) fn wait_idle(&self) {
        self.writer.wait_idle();
    }
}
