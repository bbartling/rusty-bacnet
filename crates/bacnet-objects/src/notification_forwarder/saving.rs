//! When a forwarder saves its Subscribed_Recipients (Clause 12.51.9).
//!
//! A write saves the new list before the forwarder serves it. Between writes
//! the list still changes: entries lapse, and each entry's served minutes fall
//! by one a minute. The operation task calls the object every second, and
//! each call compares the minutes the list serves with the copy last saved. A
//! lapse saves at once; falling minutes save at most once a minute. A saved
//! entry therefore never carries more than about a minute beyond what it had
//! left, so a device that restarts often still sees each entry run out.
//!
//! A failed save is logged, counted in [`ForwarderSaveCounters`] and retried
//! a minute later; the copy in storage keeps the last list that was saved.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bacnet_types::constructed::BACnetEventNotificationSubscription;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;

use super::persistence::SubscribedRecipientsPersistence;
use crate::subscribed_recipients::SubscribedRecipients;

/// The least time between two saves the operation task makes for falling
/// minutes or to retry a failed save.
const RESAVE_INTERVAL: Duration = Duration::from_secs(60);

/// Lifetime totals of one forwarder's Subscribed_Recipients saves, shared
/// with the object: take it with
/// [`save_counters`](super::NotificationForwarderObject::save_counters)
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

/// A forwarder's storage and what it last saved there.
pub(super) struct SavedCopy {
    persistence: Arc<dyn SubscribedRecipientsPersistence>,
    saved: Vec<BACnetEventNotificationSubscription>,
    /// When the operation task last tried to save, on the store's clock.
    last_attempt: Option<Duration>,
    counters: ForwarderSaveCounters,
}

impl SavedCopy {
    /// Storage that holds `saved`, as loaded when the forwarder was built.
    pub(super) fn new(
        persistence: Arc<dyn SubscribedRecipientsPersistence>,
        saved: Vec<BACnetEventNotificationSubscription>,
        counters: ForwarderSaveCounters,
    ) -> Self {
        Self {
            persistence,
            saved,
            last_attempt: None,
            counters,
        }
    }

    fn save(
        &mut self,
        oid: ObjectIdentifier,
        list: Vec<BACnetEventNotificationSubscription>,
    ) -> Result<(), Error> {
        match self.persistence.save(oid, &list) {
            Ok(()) => {
                self.saved = list;
                Ok(())
            }
            Err(error) => {
                self.counters.record_failure();
                tracing::warn!(
                    forwarder = %oid,
                    %error,
                    "Failed to save Notification Forwarder Subscribed_Recipients"
                );
                Err(error)
            }
        }
    }

    /// Save the list a write leaves in `store`, before the forwarder serves
    /// it.
    pub(super) fn save_written(
        &mut self,
        oid: ObjectIdentifier,
        store: &SubscribedRecipients,
    ) -> Result<(), Error> {
        self.save(oid, store.subscriptions())
    }

    /// Bring the saved copy up to date from the operation task: at once when
    /// an entry lapsed, and otherwise at most once every
    /// [`RESAVE_INTERVAL`] while the served minutes differ from the copy.
    pub(super) fn keep_current(
        &mut self,
        oid: ObjectIdentifier,
        store: &SubscribedRecipients,
        lapsed: bool,
    ) {
        let current = store.subscriptions();
        if current == self.saved {
            return;
        }
        let now = store.current_time();
        let due = lapsed
            || self
                .last_attempt
                .is_none_or(|at| now.saturating_sub(at) >= RESAVE_INTERVAL);
        if !due {
            return;
        }
        self.last_attempt = Some(now);
        let _ = self.save(oid, current);
    }

    /// The store's clock changed: times kept on the old one no longer apply.
    pub(super) fn clock_changed(&mut self) {
        self.last_attempt = None;
    }
}
