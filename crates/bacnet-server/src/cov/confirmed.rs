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
//! and holds its coordinate off for one full retry cycle. Fanouts inside the
//! hold-off skip the coordinate and schedule nothing. The first fanout after it
//! reports the change again; for a context it hands every reference to one
//! follow-up, since the failed report's changes may sit on other objects. A
//! subscriber that stopped answering, or keeps refusing, therefore costs at most
//! one delivery attempt per hold-off however often its objects change, and
//! cannot keep the in-flight slots to itself. Shutdown and cancellation clear
//! the mark without a hold-off.
//!
//! The standard delivers a confirmed notification with the usual APDU timeout and
//! retries (Clause 5.4.4) and asks nothing further once they end. Reporting again
//! after a hold-off is local policy.
//!
//! A replaced ordinary or Single subscription starts with a fresh marker. A
//! context gets one when its route changes, and when a re-subscription that
//! lists references arrives while it is busy, so the initial report is not held
//! behind the old one (Clauses 13.14.2 and 13.16.2). The old marker is fenced:
//! its outstanding report stops retrying, and can neither complete nor unmark
//! the coordinate.
//!
//! A fenced report may still have reached the subscriber, whose Ack then counts
//! for nothing. So when the old marker owed a follow-up (its report was
//! outstanding, or had failed and was holding off or owed), every reference of
//! the context is evaluated again, and the untimestamped references the
//! re-subscription kept first forget their baselines (#923). The follow-up then
//! reports their current value even if it went back to the baseline after the
//! fenced report, which the subscriber would otherwise keep showing. Timestamped
//! references need no reset: the fenced report's history returns to their queue,
//! and a change back is captured as a change of its own.

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
    /// End of the hold-off after a failed report. Once it has passed, a
    /// context still owes one follow-up of all its references.
    hold_until: Option<Instant>,
    /// Replaced by a fresh marker: an outstanding report stops retrying.
    fenced: bool,
}

#[derive(Debug, Default)]
struct FlightShared {
    state: Mutex<FlightState>,
    fenced: Notify,
}

/// Outstanding confirmed report and hold-off of one coordinate, shared by every
/// snapshot of it. For a Multiple context it also identifies the current route
/// incarnation: replacing it fences snapshots taken before.
#[derive(Debug, Clone, Default)]
pub(super) struct FlightMarker(Arc<FlightShared>);

impl FlightMarker {
    fn state(&self) -> MutexGuard<'_, FlightState> {
        // A panic while holding this lock leaves only plain values.
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether both handles name the same coordinate incarnation.
    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// An outstanding report, or a failed one still holding off or owed.
    fn owes_follow_up(&self) -> bool {
        let state = self.state();
        state.ticket != 0 || state.hold_until.is_some()
    }

    /// No outstanding report and no hold-off in force at `now`.
    fn idle(&self, now: Instant) -> bool {
        let state = self.state();
        state.ticket == 0 && state.hold_until.is_none_or(|until| now >= until)
    }

    /// Clear a hold-off that has passed, reporting whether there was one.
    fn take_owed(&self, now: Instant) -> bool {
        let mut state = self.state();
        let owed = state.ticket == 0 && state.hold_until.is_some_and(|until| now >= until);
        if owed {
            state.hold_until = None;
        }
        owed
    }

    /// Whether `ticket` is the outstanding report.
    pub(super) fn holds(&self, ticket: ObservationTicket) -> bool {
        self.state().ticket == ticket.get()
    }

    /// A fresh marker replaced this one: stop its outstanding report.
    pub(super) fn fence(&self) {
        self.state().fenced = true;
        self.0.fenced.notify_waiters();
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
    /// The coordinate already has an outstanding report, is holding off after
    /// a failure, or was acknowledged since it was captured. That outcome owns
    /// the follow-up.
    Busy,
}

/// The outstanding confirmed report of one notification, on its one
/// coordinate: a subscription or a whole context.
///
/// Dropping it ends the report without a hold-off: after the Ack has completed
/// the baselines, on shutdown and cancellation, or once it is fenced.
#[derive(Debug)]
#[must_use = "dropping a flight ends the outstanding report"]
pub(crate) struct ConfirmedFlight {
    marker: FlightMarker,
    ticket: ObservationTicket,
}

impl ConfirmedFlight {
    /// Retries exhausted or refused: end the report and hold its coordinate off
    /// for `hold_off`, leaving the baselines where they were.
    pub(crate) fn failed(self, hold_off: Duration) {
        self.marker
            .settle(self.ticket, Some(Instant::now() + hold_off));
    }

    /// Complete once a fresh marker has replaced this report's, after a route
    /// change or a renewal: retrying it on the old incarnation would only land
    /// after the replacement's own report.
    pub(crate) async fn fenced(&self) {
        loop {
            let notified = self.marker.0.fenced.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.marker.state().fenced {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for ConfirmedFlight {
    fn drop(&mut self) {
        self.marker.settle(self.ticket, None);
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

    /// Whether an idle context still owes the follow-up of a failed report,
    /// whose hold-off has passed. Taking it clears it: the caller fans every
    /// reference of the context out, since the failed report's changes may sit
    /// on objects other than the one that fanned out now.
    pub(crate) fn take_owed_context(&self, context: &MultipleContextKey) -> bool {
        context.confirmed
            && self
                .multiple_context_references(context)
                .next()
                .is_some_and(|entry| entry.flight.take_owed(Instant::now()))
    }

    /// Mark the coordinate of one confirmed notification's references
    /// outstanding, under the report's single ticket.
    pub(crate) fn begin_confirmed<'a>(
        &mut self,
        completion: PreparedCovCompletion,
        snapshots: impl IntoIterator<Item = &'a CovSubscriptionSnapshot>,
    ) -> Result<ConfirmedFlight, BeginRefusal> {
        let PreparedCovCompletion::Confirmed(ticket) = completion else {
            debug_assert!(false, "a confirmed report prepares a confirmed completion");
            return Err(BeginRefusal::Busy);
        };
        let now = Instant::now();
        let mut marker: Option<FlightMarker> = None;
        for snapshot in snapshots {
            if !self.is_current(snapshot) {
                return Err(BeginRefusal::NotCurrent);
            }
            if !self.confirmed_idle_at(snapshot, now) {
                return Err(BeginRefusal::Busy);
            }
            let current = &self.subs[snapshot.key()].flight;
            // Live references of one report share their subscription's or
            // context's marker.
            debug_assert!(marker.as_ref().is_none_or(|known| known.same(current)));
            marker.get_or_insert_with(|| current.clone());
        }
        let Some(marker) = marker else {
            return Err(BeginRefusal::NotCurrent);
        };
        marker.state().ticket = ticket.get();
        Ok(ConfirmedFlight { marker, ticket })
    }

    /// Choose the marker a Multiple context keeps after this admission. A route
    /// change always starts a new one, as does a re-subscription listing
    /// references while the context is busy. Returns it, with the marker it
    /// replaces, if any.
    pub(super) fn context_flight(
        &self,
        context: &MultipleContextKey,
        route: &super::SubscriberEndpoint,
        lists_references: bool,
    ) -> (FlightMarker, Option<FlightMarker>) {
        let current = self
            .subs
            .values()
            .find(|entry| entry.key.multiple_context() == Some(context))
            .map(|entry| (entry.endpoint() == *route, entry.flight.clone()));
        match current {
            Some((true, flight)) if !lists_references || flight.idle(Instant::now()) => {
                (flight, None)
            }
            Some((_, replaced)) => (FlightMarker::default(), Some(replaced)),
            None => (FlightMarker::default(), None),
        }
    }

    /// Fence a marker a fresh one replaced, once the references `listed` by the
    /// replacing request are published. If its report was outstanding, or
    /// failed and still owed a follow-up, nothing on the old marker can finish
    /// the job, yet the report may have reached the subscriber: every
    /// reference, kept or relisted, is evaluated again, and each kept
    /// untimestamped one forgets its baseline first, so the follow-up reports
    /// its current value (#923). Listed references have no baseline either, so
    /// whichever of this follow-up and the initial report goes first carries
    /// them as first reports, and the other finds the context busy.
    pub(super) fn fence_context_flight(
        &mut self,
        context: &MultipleContextKey,
        replaced: &FlightMarker,
        listed: &HashSet<CovSubscriptionKey>,
    ) {
        if replaced.owes_follow_up() {
            // Measured against a baseline the subscriber may have left behind,
            // a value that went back to it would never be reported again.
            for entry in self.subs.values_mut() {
                if entry.key.multiple_context() == Some(context)
                    && entry.issue_confirmed_notifications
                    && !entry.timestamped
                    && !listed.contains(&entry.key)
                {
                    entry.subscription.last_notified_observation = None;
                }
            }
            self.revisits.request(
                self.multiple_context_references(context)
                    .map(|entry| entry.key().clone()),
            );
        }
        replaced.fence();
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
