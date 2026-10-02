//! Claims on drained timestamped changes, and the one report an unconfirmed
//! context sends at a time (#986).

use std::sync::Arc;

use bacnet_objects::clock::ClockFrame;

use super::{CovSubscriptionKey, MultipleContextKey, TimedChange, TimedStore};
use crate::cov::CovRevisits;

/// Changes drained into one notification. Unless [`TimedClaim::commit`] is
/// called once the notification is delivered, dropping the claim returns the
/// changes to their references.
///
/// A report's claim conveys each reference's last claimed change as its
/// current state. A claim split off by [`TimedClaim::split_earliest`] carries
/// history only, for a notification that goes out before the report's last.
#[derive(Debug)]
pub(crate) struct TimedClaim {
    store: TimedStore,
    changes: Vec<(CovSubscriptionKey, u64, Vec<TimedChange>)>,
    history_only: bool,
    /// Whether returning these changes applies the context bound.
    evict: bool,
}

impl TimedClaim {
    pub(crate) fn new(store: TimedStore) -> Self {
        Self {
            store,
            changes: Vec::new(),
            history_only: false,
            evict: true,
        }
    }

    /// Return these changes without applying the context bound: a report
    /// planned to send them and only defers them, so the bound must not drop
    /// what it just drained (#986).
    pub(crate) fn without_eviction(mut self) -> Self {
        self.evict = false;
        self
    }

    /// Give these changes up, counting each as dropped: one of them alone
    /// does not fit a notification, so every attempt to send it would fail.
    pub(crate) fn discard(mut self, reason: &str) {
        let store = self.store.lock();
        for (key, _, changes) in self.changes.drain(..) {
            store.dropped(&key, changes.len(), reason);
        }
    }

    pub(crate) fn add(
        &mut self,
        key: CovSubscriptionKey,
        incarnation: u64,
        changes: Vec<TimedChange>,
    ) {
        if !changes.is_empty() {
            self.changes.push((key, incarnation, changes));
        }
    }

    /// Move the `count` oldest changes of [`Self::earlier`] (all of them, if
    /// fewer) into a claim of their own, for a notification that goes out
    /// before this one. Each
    /// reference keeps its latest change here, so this claim still conveys
    /// every reference's current state.
    pub(crate) fn split_earliest(&mut self, count: usize) -> Self {
        let mut part = Self {
            store: self.store.clone(),
            changes: Vec::new(),
            history_only: true,
            evict: self.evict,
        };
        let cut = {
            let earlier = self.earlier();
            let moved = count.min(earlier.len());
            moved.checked_sub(1).map(|last| earlier[last].1.seq)
        };
        let Some(cut) = cut else {
            return part;
        };
        let kept = usize::from(!self.history_only);
        for (key, incarnation, changes) in &mut self.changes {
            let movable = changes.len().saturating_sub(kept);
            let moved = changes[..movable].partition_point(|change| change.seq <= cut);
            if moved > 0 {
                part.changes
                    .push((key.clone(), *incarnation, changes.drain(..moved).collect()));
            }
        }
        self.changes.retain(|(_, _, changes)| !changes.is_empty());
        part
    }

    /// The latest claimed change of a reference: its current conveyed state.
    /// A history-only claim conveys none.
    pub(crate) fn latest(&self, key: &CovSubscriptionKey) -> Option<&TimedChange> {
        if self.history_only {
            return None;
        }
        self.changes
            .iter()
            .find(|(k, _, _)| k == key)
            .and_then(|(_, _, changes)| changes.last())
    }

    /// Claimed changes conveyed as history, in capture order: those before
    /// each reference's latest one, or every change of a history-only claim.
    /// Each goes out as distinct timestamped values.
    pub(crate) fn earlier(&self) -> Vec<(&CovSubscriptionKey, &TimedChange)> {
        let kept = usize::from(!self.history_only);
        let mut all: Vec<_> = self
            .changes
            .iter()
            .flat_map(|(key, _, changes)| {
                let earlier = &changes[..changes.len().saturating_sub(kept)];
                earlier.iter().map(move |change| (key, change))
            })
            .collect();
        all.sort_by_key(|(_, change)| change.seq);
        all
    }

    /// Each claimed reference with its last claimed change.
    pub(crate) fn last_changes(&self) -> impl Iterator<Item = (&CovSubscriptionKey, &TimedChange)> {
        self.changes
            .iter()
            .filter_map(|(key, _, changes)| Some((key, changes.last()?)))
    }

    /// Sequence and clock frame of the most recently captured claimed change.
    pub(crate) fn newest(&self) -> Option<(u64, ClockFrame)> {
        self.changes
            .iter()
            .filter_map(|(_, _, changes)| changes.last())
            .max_by_key(|change| change.seq)
            .map(|change| (change.seq, change.frame))
    }

    /// The notification carrying these changes was delivered: retire them.
    pub(crate) fn commit(mut self) {
        let mut store = self.store.lock();
        for (key, incarnation, changes) in self.changes.drain(..) {
            if let Some(last) = changes.last() {
                store.commit(&key, incarnation, last.seq);
            }
        }
    }
}

impl Drop for TimedClaim {
    fn drop(&mut self) {
        if self.changes.is_empty() {
            return;
        }
        let mut store = self.store.lock();
        for (key, incarnation, changes) in self.changes.drain(..) {
            store.requeue(&key, incarnation, changes, self.evict);
        }
    }
}

/// The one report an unconfirmed context is sending (#986).
///
/// Its parts go out one await apart, and an unconfirmed context has no
/// outstanding-report mark, so another fanout could drain a newer change and
/// send it between them: the subscriber would see a reference move back to
/// older history. While a turn is held, other fanouts of the context stand
/// back and leave their changes queued. Dropping the turn, after the last
/// part or on any early return, hands the context to one follow-up if a
/// fanout stood back.
#[must_use = "dropping the turn ends the report"]
pub(crate) struct SendTurn {
    store: TimedStore,
    context: MultipleContextKey,
    revisits: Arc<CovRevisits>,
    keys: Vec<CovSubscriptionKey>,
}

impl SendTurn {
    /// Take the turn of `context`, unless a report of it is still going out.
    /// `keys` are the context's references, for the follow-up.
    pub(crate) fn begin(
        store: &TimedStore,
        context: &MultipleContextKey,
        revisits: &Arc<CovRevisits>,
        keys: Vec<CovSubscriptionKey>,
    ) -> Option<Self> {
        store.lock().begin_send(context).then(|| Self {
            store: store.clone(),
            context: context.clone(),
            revisits: Arc::clone(revisits),
            keys,
        })
    }
}

impl Drop for SendTurn {
    fn drop(&mut self) {
        let owed = self.store.lock().end_send(&self.context);
        if owed {
            self.revisits.request(std::mem::take(&mut self.keys));
        }
    }
}
