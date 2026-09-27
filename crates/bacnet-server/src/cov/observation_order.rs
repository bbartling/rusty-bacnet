//! Local preparation order for whole, successfully sent unconfirmed observations.
use super::{CovObservation, CovSubscriptionSnapshot, CovSubscriptionTable};
use std::sync::atomic::{AtomicU64, Ordering};

/// Existing table identity also owns one checked counter. No extra per-reference Arc.
#[derive(Debug, Default)]
pub(super) struct ObservationOwner {
    issued: AtomicU64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ObservationTicket(u64);

/// Only a complete eligible preparation may obtain this internal completion authority.
/// Confirmed reports retain admission-time completion without consuming tickets.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PreparedCovCompletion {
    Confirmed,
    Unconfirmed(ObservationTicket),
}
impl CovSubscriptionSnapshot {
    /// Call synchronously after complete capture/qualification, before any later await.
    /// For shared ordinary capture, prepare each applicable reference under that view.
    pub(crate) fn prepare_completion(&self) -> Option<PreparedCovCompletion> {
        if self.issue_confirmed_notifications {
            return Some(PreparedCovCompletion::Confirmed);
        }
        self.owner
            .issued
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()
            .map(|n| PreparedCovCompletion::Unconfirmed(ObservationTicket(n + 1)))
    }
}
impl CovSubscriptionTable {
    /// Commit a complete observation and successful marker together under the caller's
    /// table write guard. Issued-but-failed/canceled work never advances this marker.
    pub(crate) fn complete_observation(
        &mut self,
        snapshot: &CovSubscriptionSnapshot,
        completion: PreparedCovCompletion,
        value: CovObservation,
    ) -> bool {
        if !self.is_current(snapshot) {
            return false;
        }
        let entry = self.subs.get_mut(snapshot.key()).expect("current entry");
        match (snapshot.issue_confirmed_notifications, completion) {
            (true, PreparedCovCompletion::Confirmed) => {}
            (false, PreparedCovCompletion::Unconfirmed(ticket)) => {
                if ticket.0 <= entry.last_successful_ticket {
                    return false;
                }
                entry.last_successful_ticket = ticket.0;
            }
            _ => return false,
        }
        entry.subscription.last_notified_observation = Some(value);
        true
    }
    /// Test setup still uses real reservation and completion, not a baseline bypass.
    #[cfg(test)]
    pub(crate) fn complete_for_test(
        &mut self,
        snapshot: &CovSubscriptionSnapshot,
        value: CovObservation,
    ) -> bool {
        snapshot
            .prepare_completion()
            .is_some_and(|completion| self.complete_observation(snapshot, completion, value))
    }
}

#[cfg(test)]
mod tests;
