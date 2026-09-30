//! Outstanding confirmed reports, their acknowledgment and the pause after a
//! failure (#896).
//!
//! A confirmed COV notification completes its references' baselines only when
//! the subscriber acknowledges it
//! ([`CovSubscriptionTable::complete_observation`]). Until then its coordinate
//! has one outstanding report, marked with that report's ticket. The coordinate
//! is an ordinary or Single subscription, or a whole COV-multiple context: every
//! notification to a context has to carry all the timestamped changes queued for
//! it (Clauses 13.1, 13.16.3.1.2.3 and 13.17.1.1.5), so one reference's report
//! cannot be outstanding while a sibling's goes out.
//!
//! Fanouts skip a marked coordinate, so its later changes wait. The Ack clears
//! the mark and hands the coordinate's references to [`CovRevisits`], and the
//! server then reports, in one notification, whatever changed meanwhile.
//!
//! A report that runs out of retries or is answered with an Error clears its mark
//! and holds its coordinate off for one retry cycle. Fanouts inside the hold-off
//! skip the coordinate and schedule nothing; the first fanout after it reports the
//! change again. A subscriber that stopped answering, or keeps refusing, therefore
//! costs at most one delivery attempt per hold-off however often its objects
//! change, and cannot keep the in-flight slots to itself. Shutdown and
//! cancellation clear the mark without a hold-off.
//!
//! The standard delivers a confirmed notification with the usual APDU timeout and
//! retries (Clause 5.4.4) and asks nothing further once they end. Reporting again
//! after a hold-off is local policy.
//!
//! A replaced ordinary or Single subscription starts with a fresh marker. A
//! context gets one when its route changes, and when a re-subscription that
//! lists references arrives while it is busy, so the initial report goes out at
//! once (Clauses 13.14.2 and 13.16.2). An older report can then neither complete
//! nor unmark the coordinate.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

use super::observation_order::{ObservationTicket, PreparedCovCompletion};
use super::{
    CovSubscriptionKey, CovSubscriptionSnapshot, CovSubscriptionTable, MultipleContextKey,
};

#[derive(Debug, Default)]
struct FlightState {
    /// Ticket of the outstanding report, or zero for none.
    ticket: u64,
    /// End of the hold-off after a failed report.
    hold_until: Option<Instant>,
}

/// Outstanding confirmed report and hold-off of one coordinate, shared by every
/// snapshot of it. For a Multiple context it also identifies the current route
/// incarnation: replacing it fences snapshots taken before.
#[derive(Debug, Clone, Default)]
pub(super) struct FlightMarker(Arc<Mutex<FlightState>>);

impl FlightMarker {
    fn state(&self) -> MutexGuard<'_, FlightState> {
        // A panic while holding this lock leaves only a ticket and an instant.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether both handles name the same coordinate incarnation.
    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn outstanding(&self) -> bool {
        self.state().ticket != 0
    }

    /// No outstanding report and no hold-off in force at `now`.
    fn idle(&self, now: Instant) -> bool {
        let state = self.state();
        state.ticket == 0 && state.hold_until.is_none_or(|until| now >= until)
    }

    /// Whether `ticket` is the outstanding report.
    pub(super) fn holds(&self, ticket: ObservationTicket) -> bool {
        self.state().ticket == ticket.get()
    }

    /// End the report `ticket` if it is still outstanding.
    fn settle(&self, ticket: ObservationTicket, hold_until: Option<Instant>) {
        let mut state = self.state();
        if state.ticket == ticket.get() {
            state.ticket = 0;
            state.hold_until = hold_until;
        }
    }
}

/// Why [`CovSubscriptionTable::begin_confirmed`] refused a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BeginRefusal {
    /// A reference was removed, replaced, moved to another route or expired
    /// since it was captured. Its live state deserves a fresh look.
    NotCurrent,
    /// A coordinate already has an outstanding report, is holding off after a
    /// failure, or was acknowledged since it was captured. That outcome owns
    /// the follow-up.
    Busy,
}

/// The outstanding confirmed report of one notification.
///
/// Dropping it ends the report without a hold-off: after the Ack has completed
/// the baselines, or on shutdown and cancellation.
#[derive(Debug)]
#[must_use = "dropping a flight ends the outstanding report"]
pub(crate) struct ConfirmedFlight {
    markers: Vec<FlightMarker>,
    ticket: ObservationTicket,
}

impl ConfirmedFlight {
    /// Retries exhausted or refused: end the report and hold its coordinates
    /// off for `hold_off`, leaving their baselines where they were.
    pub(crate) fn failed(mut self, hold_off: Duration) {
        let until = Instant::now() + hold_off;
        for marker in self.markers.drain(..) {
            marker.settle(self.ticket, Some(until));
        }
    }
}

impl Drop for ConfirmedFlight {
    fn drop(&mut self) {
        for marker in &self.markers {
            marker.settle(self.ticket, None);
        }
    }
}

impl CovSubscriptionTable {
    /// The live entry `snapshot` was taken from, whatever its expiry.
    fn live_entry(&self, snapshot: &CovSubscriptionSnapshot) -> Option<&CovSubscriptionSnapshot> {
        if !Arc::ptr_eq(&self.owner, &snapshot.owner) {
            return None;
        }
        self.subs.get(snapshot.key()).filter(|entry| {
            entry.generation == snapshot.generation && entry.flight.same(&snapshot.flight)
        })
    }

    fn confirmed_idle_at(&self, snapshot: &CovSubscriptionSnapshot, now: Instant) -> bool {
        if !snapshot.issue_confirmed_notifications {
            return true;
        }
        // A snapshot that is no longer live is dropped by the liveness checks.
        self.live_entry(snapshot).is_none_or(|entry| {
            entry.flight.idle(now)
                && entry.last_successful_ticket == snapshot.last_successful_ticket
        })
    }

    /// Whether a fanout may report this ordinary or Single subscription now: no
    /// confirmed report of it is outstanding or holding it off, and none was
    /// acknowledged after `snapshot` was taken, so the snapshot's baseline is
    /// still the live one. Always true for unconfirmed subscriptions.
    pub(crate) fn confirmed_idle(&self, snapshot: &CovSubscriptionSnapshot) -> bool {
        self.confirmed_idle_at(snapshot, Instant::now())
    }

    /// The same for a whole COV-multiple context: its marker is idle and no live
    /// snapshot among `snapshots` predates an acknowledgment. Always true for an
    /// unconfirmed context.
    pub(crate) fn context_idle(
        &self,
        context: &MultipleContextKey,
        snapshots: &[CovSubscriptionSnapshot],
    ) -> bool {
        if !context.confirmed {
            return true;
        }
        let now = Instant::now();
        self.multiple_context_references(context)
            .next()
            .is_none_or(|entry| entry.flight.idle(now))
            && snapshots
                .iter()
                .all(|snapshot| self.confirmed_idle_at(snapshot, now))
    }

    /// Mark the coordinates of one confirmed notification's references
    /// outstanding, all or none, under the report's single ticket.
    pub(crate) fn begin_confirmed<'a>(
        &mut self,
        completion: PreparedCovCompletion,
        snapshots: impl IntoIterator<Item = &'a CovSubscriptionSnapshot>,
    ) -> Result<ConfirmedFlight, BeginRefusal> {
        let PreparedCovCompletion::Confirmed(ticket) = completion else {
            return Err(BeginRefusal::Busy);
        };
        let now = Instant::now();
        let mut markers: Vec<FlightMarker> = Vec::new();
        for snapshot in snapshots {
            if !self.is_current(snapshot) {
                return Err(BeginRefusal::NotCurrent);
            }
            if !self.confirmed_idle_at(snapshot, now) {
                return Err(BeginRefusal::Busy);
            }
            let marker = &self.subs[snapshot.key()].flight;
            if !markers.iter().any(|known| known.same(marker)) {
                markers.push(marker.clone());
            }
        }
        for marker in &markers {
            marker.state().ticket = ticket.get();
        }
        Ok(ConfirmedFlight { markers, ticket })
    }

    /// Choose the marker a Multiple context keeps after this admission. A route
    /// change always starts a new one, as does a re-subscription listing
    /// references while the context is busy. Returns it, with whether an
    /// outstanding report was fenced off.
    pub(super) fn context_flight(
        &self,
        context: &MultipleContextKey,
        route: &super::SubscriberEndpoint,
        lists_references: bool,
    ) -> (FlightMarker, bool) {
        let current = self
            .subs
            .values()
            .find(|entry| entry.key.multiple_context() == Some(context))
            .map(|entry| (entry.endpoint() == *route, entry.flight.clone()));
        let Some((same_route, flight)) = current else {
            return (FlightMarker::default(), false);
        };
        if same_route && (!lists_references || flight.idle(Instant::now())) {
            (flight, false)
        } else {
            let fenced = flight.outstanding();
            (FlightMarker::default(), fenced)
        }
    }

    /// References owed a fresh evaluation after an acknowledgment.
    pub(crate) fn revisits(&self) -> &Arc<CovRevisits> {
        &self.revisits
    }
}

/// References whose confirmed report was acknowledged or fenced off, and so need
/// evaluating again. The server drains them in a background task and fans them
/// out through the usual path, which reports only what differs from each
/// baseline.
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

    /// Queued references, without taking them.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> HashSet<CovSubscriptionKey> {
        self.pending().clone()
    }

    /// Drop a removed reference's pending evaluation.
    pub(super) fn forget(&self, key: &CovSubscriptionKey) {
        self.pending().remove(key);
    }
}

#[cfg(test)]
mod tests;
