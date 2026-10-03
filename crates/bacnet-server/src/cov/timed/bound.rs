//! Eviction under the local history bound of a COV-multiple context (#986,
//! #1039, #1163); the policy and the memory ceiling it implies are in the
//! parent module's docs.
//!
//! Eviction may take any pending change except, per reference, its newest
//! and its change in delivery: the change a part went out ahead of, sent
//! one value per notification (#1090). Parts go out in capture order, one
//! report at a time, so the change a part last went out ahead of is the only
//! one of the reference whose later values can still be waiting; each
//! reference records just that one.

use super::{CovSubscriptionKey, DropReason, TimedHistories, TimedHistory};

/// Position of the oldest change of `history` that eviction may take: one
/// that is neither the reference's newest nor its change in delivery.
fn evictable(history: &TimedHistory) -> Option<usize> {
    let newest = history.entries.len().checked_sub(1)?;
    (0..newest).find(|&at| history.entries[at].seq != history.in_delivery)
}

impl TimedHistories {
    /// A part carrying some values of change `seq` of `key` went out ahead of
    /// the rest: that change is in delivery until its last value is, and the
    /// bound keeps it meanwhile (#1163).
    pub(super) fn deliver_by_value(
        &mut self,
        key: &CovSubscriptionKey,
        incarnation: u64,
        seq: u64,
    ) {
        if let Some(history) = self.incarnation_mut(key, incarnation) {
            history.in_delivery = seq;
        }
    }

    /// Evict pending changes of `key`'s context while it is over its bound:
    /// this reference's oldest evictable change first, then the oldest in the
    /// context. Stops when only changes eviction may not take are left.
    pub(super) fn enforce_bound(&mut self, key: &CovSubscriptionKey) {
        let Some(context) = key.multiple_context().cloned() else {
            return;
        };
        let Some(capacity) = self.terms.get(&context).map(|terms| terms.capacity()) else {
            return;
        };
        while self.context_bytes.get(&context).copied().unwrap_or(0) > capacity {
            let victim = match self.histories.get(key).and_then(evictable) {
                Some(at) => Some((key.clone(), at)),
                None => self
                    .histories
                    .iter()
                    .filter(|(k, _)| k.multiple_context() == Some(&context))
                    .filter_map(|(k, h)| evictable(h).map(|at| (k, at, h.entries[at].seq)))
                    .min_by_key(|&(_, _, seq)| seq)
                    .map(|(k, at, _)| (k.clone(), at)),
            };
            let Some((victim, at)) = victim else {
                return;
            };
            let evicted = self
                .histories
                .get_mut(&victim)
                .and_then(|h| h.entries.remove(at))
                .expect("victim has an evictable change");
            self.release_bytes(&victim, evicted.cost);
            self.dropped(&victim, 1, DropReason::HistoryFull);
        }
    }

    /// Return `bytes` of `key`'s pending changes to its context's bound.
    pub(super) fn release_bytes(&mut self, key: &CovSubscriptionKey, bytes: usize) {
        let Some(context) = key.multiple_context() else {
            return;
        };
        if let Some(used) = self.context_bytes.get_mut(context) {
            *used = used.saturating_sub(bytes);
            if *used == 0 {
                self.context_bytes.remove(context);
            }
        }
    }
}
