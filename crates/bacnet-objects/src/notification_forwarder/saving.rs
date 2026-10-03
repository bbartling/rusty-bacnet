//! When a forwarder saves its lists (Clauses 12.51.8 and 12.51.9, #1270).
//!
//! A write to Recipient_List or Subscribed_Recipients saves both lists before
//! the forwarder serves the new one, and a write that cannot be saved is
//! refused with DEVICE / OPERATIONAL_PROBLEM, leaving the old list. The bundled
//! server stages such a write ([`DurableWrites`](crate::durable::DurableWrites)):
//! the save runs on the forwarder's writer thread while the database guard is
//! dropped, and the write then takes the saved lists without saving again. A
//! write that was not staged queues its save and waits for it where it is.
//!
//! A staged write its request never makes, because the request failed first
//! or is gone, is dropped. Its save may already have put lists in storage
//! that the forwarder never served, so the forwarder queues a save of the
//! lists it does serve at once; a restart then serves those.
//!
//! Between writes Subscribed_Recipients still changes: entries lapse, and each
//! entry's served minutes fall by one a minute. The operation task calls the
//! object every second, and each call compares the lists the forwarder serves
//! with the copy storage last confirmed. A lapse queues a save at once;
//! falling minutes queue one at most once a minute. These saves coalesce on
//! the writer, so a burst costs one save of the latest lists. A saved entry
//! therefore never carries more than about a minute beyond what it had left,
//! so a device that restarts often still sees each entry run out.
//!
//! A failed save is logged and counted in [`ForwarderSaveCounters`]. The
//! operation task retries its saves a minute later, and storage keeps the last
//! lists that were saved.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bacnet_types::constructed::BACnetDestination;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};

use super::persistence::{ForwarderSnapshot, NotificationForwarderPersistence};
use crate::durable::{Event, SaveTicket, SaveWait, SaveWriter, StageStep};
use crate::subscribed_recipients::SubscribedRecipients;

/// The least time between two saves the operation task makes for falling
/// minutes or to retry a failed save.
const RESAVE_INTERVAL: Duration = Duration::from_secs(60);

/// Lifetime totals of one forwarder's saves, shared with the object: take it
/// with [`save_counters`](super::NotificationForwarderObject::save_counters)
/// before the object joins a database, and read it at any time after. Each
/// total saturates at `u64::MAX`.
#[derive(Clone, Debug, Default)]
pub struct ForwarderSaveCounters {
    failed_saves: Arc<AtomicU64>,
}

impl ForwarderSaveCounters {
    /// Saves the persistence refused: those for a write, which the write then
    /// fails with, and those the operation task makes, which it retries.
    pub fn failed_saves(&self) -> u64 {
        self.failed_saves.load(Ordering::Relaxed)
    }

    fn record_failure(&self) {
        #[allow(deprecated, reason = "try_update needs Rust 1.95; the MSRV is 1.93")]
        let _ = self
            .failed_saves
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }
}

/// The list a write leaves, in the form the forwarder holds it.
pub(super) enum NextList {
    RecipientList(Vec<BACnetDestination>),
    SubscribedRecipients(SubscribedRecipients),
}

/// A write staged for a request: the lists it leaves, saving on the writer.
struct StagedWrite {
    property: PropertyIdentifier,
    value: PropertyValue,
    /// The forwarder's write count when staged. The write takes the staged
    /// list only if no other write came between.
    base: u64,
    next: NextList,
    ticket: SaveTicket,
    /// Set when the staged write is taken or dropped, for a request that
    /// found the forwarder busy.
    released: Arc<Event>,
}

/// A forwarder's storage, its writer, and what storage last confirmed.
pub(super) struct Storage {
    writer: SaveWriter<ForwarderSnapshot>,
    /// The lists storage last confirmed, updated by the writer's thread.
    confirmed: Arc<Mutex<ForwarderSnapshot>>,
    /// When the operation task last queued a save, on the store's clock.
    last_attempt: Option<Duration>,
    /// A lapse wants the next operation task call to save without waiting
    /// for the minute.
    resave_now: bool,
    /// A staged write was dropped whose save did not fail, so storage may
    /// hold lists the forwarder never served; [`correct`](Self::correct)
    /// saves the served ones.
    correction_due: bool,
    staged: Option<StagedWrite>,
}

impl Storage {
    /// Storage for `oid` that holds `confirmed`, as loaded when the
    /// forwarder was built.
    pub(super) fn new(
        oid: ObjectIdentifier,
        persistence: Arc<dyn NotificationForwarderPersistence>,
        confirmed: ForwarderSnapshot,
        counters: ForwarderSaveCounters,
    ) -> Self {
        let confirmed = Arc::new(Mutex::new(confirmed));
        let saved = Arc::clone(&confirmed);
        let writer = SaveWriter::new(
            format!("bacnet-nf-{}-save", oid.instance_number()),
            move |snapshot: &ForwarderSnapshot| persistence.save(oid, snapshot),
            move |snapshot, result| match result {
                Ok(()) => {
                    *saved.lock().unwrap_or_else(PoisonError::into_inner) = snapshot.clone();
                }
                Err(error) => {
                    counters.record_failure();
                    tracing::warn!(
                        forwarder = %oid,
                        %error,
                        "Failed to save Notification Forwarder lists"
                    );
                }
            },
        );
        Self {
            writer,
            confirmed,
            last_attempt: None,
            resave_now: false,
            correction_due: false,
            staged: None,
        }
    }

    /// The wait for a staged write that still holds the forwarder: one whose
    /// save is running, or finished within
    /// [`STAGED_WRITE_LIFETIME`](crate::durable::STAGED_WRITE_LIFETIME). An
    /// older one is dropped.
    pub(super) fn busy(&mut self) -> Option<SaveWait> {
        self.busy_at(Instant::now())
    }

    /// [`busy`](Self::busy), judged at `now`.
    pub(super) fn busy_at(&mut self, now: Instant) -> Option<SaveWait> {
        let staged = self.staged.as_ref()?;
        if !staged.ticket.outlived_at(now) {
            return Some(SaveWait::new(Arc::clone(&staged.released)));
        }
        self.drop_staged();
        None
    }

    /// Queue a save of `snapshot` for a write of `value` to `property` that
    /// leaves `next`, and keep `next` aside until the write arrives.
    pub(super) fn stage(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        base: u64,
        next: NextList,
        snapshot: ForwarderSnapshot,
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

    /// Take the staged list for a write of `value` to `property` made at
    /// write count `base`: the list if its save succeeded, the save's error
    /// if not. `None` when no staged write matches; a staged write that does
    /// not match is dropped, since the write about to be saved supersedes it.
    pub(super) fn claim(
        &mut self,
        property: PropertyIdentifier,
        value: &PropertyValue,
        base: u64,
    ) -> Option<Result<NextList, Error>> {
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
    pub(super) fn save_now(&mut self, snapshot: ForwarderSnapshot) -> Result<(), Error> {
        self.writer.submit(snapshot).take_outcome()
    }

    /// The request that staged a write and was given `wait` is done. A
    /// staged write another request made is left alone.
    pub(super) fn release(&mut self, wait: &SaveWait) {
        if self
            .staged
            .as_ref()
            .is_some_and(|staged| staged.ticket.issued(wait))
        {
            self.drop_staged();
        }
    }

    fn drop_staged(&mut self) {
        let Some(staged) = self.staged.take() else {
            return;
        };
        staged.released.set();
        // Unless its save failed, storage holds, or is about to hold, lists
        // the forwarder never served.
        if staged.ticket.succeeded() != Some(false) {
            self.correction_due = true;
        }
    }

    /// After a staged write was dropped, queue a save of `served`, the lists
    /// the forwarder serves, at once. It lands after the dropped write's
    /// save, since saves run in order.
    pub(super) fn correct(&mut self, served: impl FnOnce() -> ForwarderSnapshot) {
        if std::mem::take(&mut self.correction_due) {
            self.writer.submit_coalescing(served());
        }
    }

    /// Bring storage up to date from the operation task: at once when an
    /// entry lapsed, and otherwise at most once every [`RESAVE_INTERVAL`]
    /// while the served lists differ from the confirmed copy. Nothing is
    /// queued while a staged write holds the forwarder, since its lists would
    /// land after this save.
    pub(super) fn keep_current(
        &mut self,
        now: Duration,
        lapsed: bool,
        current: impl FnOnce() -> ForwarderSnapshot,
    ) {
        if lapsed {
            self.resave_now = true;
        }
        if self.busy().is_some() {
            return;
        }
        // A staged write dropped just now: save the served lists below.
        self.resave_now |= std::mem::take(&mut self.correction_due);
        let current = current();
        if current
            == *self
                .confirmed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        {
            self.resave_now = false;
            return;
        }
        let due = self.resave_now
            || self
                .last_attempt
                .is_none_or(|at| now.saturating_sub(at) >= RESAVE_INTERVAL);
        if !due {
            return;
        }
        self.last_attempt = Some(now);
        self.resave_now = false;
        self.writer.submit_coalescing(current);
    }

    /// The store's clock changed: times kept on the old one no longer apply,
    /// and a staged list holds deadlines on the old clock.
    pub(super) fn clock_changed(&mut self) {
        self.last_attempt = None;
        self.drop_staged();
    }

    /// Block until every queued save has run.
    pub(super) fn wait_idle(&self) {
        self.writer.wait_idle();
    }
}
