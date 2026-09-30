//! Outstanding confirmed reports and their acknowledgment (#896).
//!
//! A confirmed COV notification completes its references' baselines only when
//! the subscriber acknowledges it
//! ([`CovSubscriptionTable::complete_observation`]). Until then each reference
//! it carries has one outstanding report, marked with that report's completion
//! ticket. Fanouts skip a marked reference, so its later changes wait. The Ack
//! clears the mark and hands the reference to [`CovRevisits`], and the server
//! then reports whatever changed while the report was outstanding. A report that
//! ends without an Ack (retries exhausted, an Error, shutdown or cancellation)
//! clears only its own mark and leaves the baseline alone, so the next ordinary
//! fanout reports the change again. It is not retried at once, which would loop
//! against a subscriber that is gone.
//!
//! The standard delivers a confirmed notification with the usual APDU timeout and
//! retry procedure (Clause 5.4.4) and asks nothing further once that ends.
//! Reporting the change again later is local policy.
//!
//! The mark is per reference, the same granularity as baselines, tickets,
//! generations and route fences. A Multiple notification marks every reference
//! it carries. A replaced reference, or one whose context moved to a new route,
//! gets a fresh marker, so an older report can neither complete it nor clear its
//! mark.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use super::observation_order::{ObservationTicket, PreparedCovCompletion};
use super::{CovSubscriptionKey, CovSubscriptionSnapshot, CovSubscriptionTable};

/// Ticket of a reference's outstanding confirmed report, or zero for none.
/// Every snapshot of one accepted entry shares it.
#[derive(Debug, Clone, Default)]
pub(super) struct FlightMarker(Arc<AtomicU64>);

impl FlightMarker {
    fn outstanding(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }

    /// Whether `ticket` is this reference's outstanding report.
    pub(super) fn holds(&self, ticket: ObservationTicket) -> bool {
        self.0.load(Ordering::Acquire) == ticket.get()
    }

    /// Clear the mark if `ticket` still owns it.
    pub(super) fn release(&self, ticket: ObservationTicket) {
        let _ = self
            .0
            .compare_exchange(ticket.get(), 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// The outstanding confirmed report of one notification's references.
///
/// An acknowledgment clears the marks as it completes the baselines. Dropping
/// the flight clears whatever marks it still owns, and nothing else.
#[derive(Debug)]
#[must_use = "dropping a flight ends the outstanding report"]
pub(crate) struct ConfirmedFlight {
    markers: Vec<(FlightMarker, ObservationTicket)>,
}

impl Drop for ConfirmedFlight {
    fn drop(&mut self) {
        for (marker, ticket) in &self.markers {
            marker.release(*ticket);
        }
    }
}

impl CovSubscriptionTable {
    /// Whether a fanout may report this reference now: it has no outstanding
    /// confirmed report, and none was acknowledged after `snapshot` was taken,
    /// so the snapshot's baseline is still the live one. Always true for
    /// unconfirmed references. Liveness is checked separately.
    pub(crate) fn confirmed_idle(&self, snapshot: &CovSubscriptionSnapshot) -> bool {
        if !snapshot.issue_confirmed_notifications {
            return true;
        }
        self.subs.get(snapshot.key()).is_some_and(|entry| {
            !entry.confirmed_flight.outstanding()
                && entry.last_successful_ticket == snapshot.last_successful_ticket
        })
    }

    /// Mark one confirmed notification's references outstanding, all or none.
    ///
    /// Refused when any reference is no longer live, already has an outstanding
    /// report, or was acknowledged after its snapshot was taken.
    pub(crate) fn begin_confirmed<'a>(
        &mut self,
        reports: impl IntoIterator<Item = (&'a CovSubscriptionSnapshot, PreparedCovCompletion)>,
    ) -> Option<ConfirmedFlight> {
        let mut markers = Vec::new();
        for (snapshot, completion) in reports {
            let PreparedCovCompletion::Confirmed(ticket) = completion else {
                return None;
            };
            if !self.is_current(snapshot) || !self.confirmed_idle(snapshot) {
                return None;
            }
            let marker = self.subs[snapshot.key()].confirmed_flight.clone();
            markers.push((marker, ticket));
        }
        for (marker, ticket) in &markers {
            marker.0.store(ticket.get(), Ordering::Release);
        }
        Some(ConfirmedFlight { markers })
    }

    /// References owed a fresh evaluation after an acknowledgment.
    pub(crate) fn revisits(&self) -> &Arc<CovRevisits> {
        &self.revisits
    }
}

/// References whose confirmed report was acknowledged and so need evaluating
/// again. The server drains them in a background task and fans them out through
/// the usual per-subscription path, which reports only what differs from the
/// acknowledged baseline.
#[derive(Debug, Default)]
pub(crate) struct CovRevisits {
    pending: Mutex<HashSet<CovSubscriptionKey>>,
    wake: Notify,
}

impl CovRevisits {
    fn pending(&self) -> MutexGuard<'_, HashSet<CovSubscriptionKey>> {
        // A panic while holding this lock leaves only a set of keys.
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue references for evaluation and wake the drain.
    pub(crate) fn request(&self, keys: impl IntoIterator<Item = CovSubscriptionKey>) {
        let mut pending = self.pending();
        let before = pending.len();
        pending.extend(keys);
        let added = pending.len() > before;
        drop(pending);
        if added {
            self.wake.notify_one();
        }
    }

    /// Wait for queued references and take them all.
    pub(crate) async fn next(&self) -> Vec<CovSubscriptionKey> {
        loop {
            let keys: Vec<_> = self.pending().drain().collect();
            if !keys.is_empty() {
                return keys;
            }
            self.wake.notified().await;
        }
    }

    /// Drop a removed reference's pending evaluation.
    pub(super) fn forget(&self, key: &CovSubscriptionKey) {
        self.pending().remove(key);
    }
}
