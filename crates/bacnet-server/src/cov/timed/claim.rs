//! Claims on drained timestamped changes and prepared untimestamped values,
//! and the one report an unconfirmed context sends at a time (#986, #1008,
//! #1038).

use std::collections::HashSet;
use std::sync::Arc;

use tokio::time::Instant;

use super::{CovSubscriptionKey, MultipleContextKey, TimedChange, TimedStore};
use crate::cov::CovRevisits;

/// Changes drained into one notification, and the untimestamped references
/// whose prepared values it carries. Unless [`TimedClaim::commit`] is called
/// once the notification is delivered, dropping the claim returns the changes
/// to their references. An untimestamped reference stays owed if it already
/// was, and becomes owed if the claim is [`TimedClaim::owing`]: its report
/// began going out without it (#1038). Otherwise an undelivered value is
/// handled like any lost notification, by the reference's next fanout.
///
/// A claim is only a set of changes. How a notification conveys them, as
/// history or as a reference's current state, is decided by the report that
/// builds it; [`TimedClaim::split_oldest`] moves the oldest of them into a
/// claim of their own, for a notification that goes out first (#986, #1008),
/// and [`TimedClaim::split_untimed`] does the same for untimestamped
/// references.
#[derive(Debug)]
pub(crate) struct TimedClaim {
    store: TimedStore,
    changes: Vec<(CovSubscriptionKey, u64, Vec<TimedChange>)>,
    /// Untimestamped references, each with its generation and, if it was
    /// owed when this report took it, since when.
    untimed: Vec<(CovSubscriptionKey, u64, Option<Instant>)>,
    /// Whether returning these changes applies the context bound.
    evict: bool,
    /// Whether an undelivered untimestamped reference becomes owed.
    owing: bool,
}

impl TimedClaim {
    pub(crate) fn new(store: TimedStore) -> Self {
        Self {
            store,
            changes: Vec::new(),
            untimed: Vec::new(),
            evict: true,
            owing: false,
        }
    }

    /// Carry the prepared values of an untimestamped reference, owed since
    /// `owed_since` if it was owed.
    pub(crate) fn add_untimed(
        &mut self,
        key: CovSubscriptionKey,
        generation: u64,
        owed_since: Option<Instant>,
    ) {
        self.untimed.push((key, generation, owed_since));
    }

    /// Move the untimestamped references among `keys` into a claim of their
    /// own, for a notification that carries their values.
    pub(crate) fn split_untimed(&mut self, keys: &HashSet<CovSubscriptionKey>) -> Self {
        let (moved, kept) = std::mem::take(&mut self.untimed)
            .into_iter()
            .partition(|(key, _, _)| keys.contains(key));
        self.untimed = kept;
        Self {
            store: self.store.clone(),
            changes: Vec::new(),
            untimed: moved,
            evict: self.evict,
            owing: self.owing,
        }
    }

    /// Give up the untimestamped references left in this claim without owing
    /// them: their values fit no notification, so a later attempt would only
    /// fail again. They are evaluated again at their next fanout.
    pub(crate) fn forgo_untimed(&mut self) {
        self.untimed.clear();
    }

    /// Return these changes without applying the context bound: a report
    /// planned to send them and only defers them, so the bound must not drop
    /// what it just drained (#986).
    pub(crate) fn without_eviction(mut self) -> Self {
        self.evict = false;
        self
    }

    /// The report this part belongs to began going out without it, so its
    /// untimestamped references are owed until a later report delivers them
    /// or finds them settled (#1038).
    pub(crate) fn owing(mut self) -> Self {
        self.owing = true;
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

    /// Move the `count` oldest claimed changes, across every reference and
    /// latest changes included (all of them, if fewer), into a claim of their
    /// own, for a notification that goes out before this one.
    pub(crate) fn split_oldest(&mut self, count: usize) -> Self {
        let mut part = Self {
            store: self.store.clone(),
            changes: Vec::new(),
            untimed: Vec::new(),
            evict: self.evict,
            owing: self.owing,
        };
        let cut = {
            let all = self.in_order();
            let moved = count.min(all.len());
            moved.checked_sub(1).map(|last| all[last].1.seq)
        };
        let Some(cut) = cut else {
            return part;
        };
        for (key, incarnation, changes) in &mut self.changes {
            let moved = changes.partition_point(|change| change.seq <= cut);
            if moved > 0 {
                part.changes
                    .push((key.clone(), *incarnation, changes.drain(..moved).collect()));
            }
        }
        self.changes.retain(|(_, _, changes)| !changes.is_empty());
        part
    }

    /// Every claimed change, in capture order.
    pub(crate) fn in_order(&self) -> Vec<(&CovSubscriptionKey, &TimedChange)> {
        let mut all: Vec<_> = self
            .changes
            .iter()
            .flat_map(|(key, _, changes)| changes.iter().map(move |change| (key, change)))
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

    /// The notification carrying these changes and values was delivered:
    /// retire them.
    pub(crate) fn commit(mut self) {
        self.untimed.clear();
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
        if self.changes.is_empty() && self.untimed.is_empty() {
            return;
        }
        let mut store = self.store.lock();
        for (key, incarnation, changes) in self.changes.drain(..) {
            store.requeue(&key, incarnation, changes, self.evict);
        }
        for (key, generation, owed_since) in self.untimed.drain(..) {
            if let Some(since) = owed_since.or_else(|| self.owing.then(Instant::now)) {
                store.owe(&key, generation, since);
            }
        }
    }
}

/// The one report an unconfirmed context is sending (#986, #1038).
///
/// Its parts go out one await apart, and an unconfirmed context has no
/// outstanding-report mark, so another fanout could send a newer change or
/// value between them: the subscriber would see a reference move back to
/// older history, or to the older value a later part carries. While a turn is
/// held, other fanouts of the context stand back and leave their changes
/// queued. Dropping the turn, after the last part or on any early return,
/// hands the context to one follow-up if a fanout stood back; the follow-up
/// reads the untimestamped values afresh.
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
