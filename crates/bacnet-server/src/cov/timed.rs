//! Retained timestamped COV-multiple changes (135-2020 §13.16.3.1.2.3, §13.17.1.1).
//!
//! A reference subscribed with `Timestamped=TRUE` must report every qualifying
//! change with the local time it happened, and keep those changes until a
//! notification carrying them is sent. Producers capture each change under
//! the database write guard; the notification builder drains the queue into a
//! [`TimedClaim`] that requeues its entries unless the notification was
//! actually transmitted.
//!
//! Local bound policy (the Standard sets none): the pending changes of one
//! COV-multiple context are limited to what one notification APDU can carry.
//! On overflow the oldest change of the same reference is evicted first, then
//! the oldest change in the context. A reference's newest change is never
//! evicted, so every reference's current state is always conveyed. Each
//! discarded change is counted in [`AtomicCovCounters::timed_changes_dropped`].

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use bacnet_objects::clock::ClockFrame;
use bacnet_services::cov_multiple::COVNotificationValue;
use tracing::warn;

use super::{AtomicCovCounters, CovObservation, CovSubscriptionKey, MultipleContextKey};

/// Octets reserved for the notification envelope and item framing when
/// deriving the per-context pending bound from the local maximum APDU.
const ENVELOPE_RESERVE: usize = 64;
/// Estimated framing per value: property identifier, optional index, value
/// open/close tags and the context-tagged Time_Of_Change.
const VALUE_FRAMING: usize = 16;

/// One captured change of a timestamped reference, ready to be conveyed.
#[derive(Debug, Clone)]
pub(crate) struct TimedChange {
    seq: u64,
    frame: ClockFrame,
    values: Vec<COVNotificationValue>,
    observation: CovObservation,
    encoded_len: usize,
}

impl TimedChange {
    /// Pair prepared values with the Device clock frame of the change. Every
    /// value carries the frame's local time as its Time_Of_Change.
    pub(crate) fn new(
        frame: ClockFrame,
        mut values: Vec<COVNotificationValue>,
        observation: CovObservation,
    ) -> Self {
        let mut encoded_len = 0;
        for value in &mut values {
            value.time_of_change = Some(frame.local_time);
            encoded_len += value.value.len() + VALUE_FRAMING;
        }
        Self {
            seq: 0,
            frame,
            values,
            observation,
            encoded_len,
        }
    }

    /// Device clock frame of the change.
    pub(crate) fn frame(&self) -> ClockFrame {
        self.frame
    }

    /// Conveyed values, each stamped with this change's local time.
    pub(crate) fn values(&self) -> &[COVNotificationValue] {
        &self.values
    }

    /// Observation this change establishes as the reference's baseline.
    pub(crate) fn observation(&self) -> &CovObservation {
        &self.observation
    }
}

#[derive(Debug)]
struct TimedHistory {
    generation: u64,
    /// Latest observation already captured or conveyed; the next change
    /// qualifies against it rather than the last completed delivery.
    baseline: Option<CovObservation>,
    /// Sequence of the newest transmitted change. An older change returned by
    /// a failed notification would contradict what was already delivered.
    committed: u64,
    entries: VecDeque<TimedChange>,
}

/// Pending timestamped changes of every live timestamped Multiple reference.
#[derive(Debug)]
pub(crate) struct TimedHistories {
    histories: HashMap<CovSubscriptionKey, TimedHistory>,
    context_bytes: HashMap<MultipleContextKey, usize>,
    next_seq: u64,
    capacity: usize,
    counters: Arc<AtomicCovCounters>,
}

impl TimedHistories {
    fn new(capacity: usize, counters: Arc<AtomicCovCounters>) -> Self {
        Self {
            histories: HashMap::new(),
            context_bytes: HashMap::new(),
            next_seq: 1,
            capacity,
            counters,
        }
    }

    /// Bind a (re)published reference generation. A renewal keeps changes not
    /// yet conveyed; its initial report is captured afresh.
    pub(super) fn reset(&mut self, key: &CovSubscriptionKey, generation: u64) {
        let history = self.histories.entry(key.clone()).or_insert(TimedHistory {
            generation,
            baseline: None,
            committed: 0,
            entries: VecDeque::new(),
        });
        history.generation = generation;
        history.baseline = None;
    }

    /// Drop the history of a removed reference.
    pub(super) fn remove(&mut self, key: &CovSubscriptionKey) {
        if let Some(history) = self.histories.remove(key) {
            let bytes: usize = history.entries.iter().map(|e| e.encoded_len).sum();
            self.release_bytes(key, bytes);
        }
    }

    /// Latest captured or conveyed observation of a live generation.
    pub(crate) fn baseline(
        &self,
        key: &CovSubscriptionKey,
        generation: u64,
    ) -> Option<&CovObservation> {
        self.history(key, generation)?.baseline.as_ref()
    }

    /// Queue a captured change and make it the reference's baseline, evicting
    /// older pending changes if the context bound is exceeded.
    pub(crate) fn push(&mut self, key: &CovSubscriptionKey, generation: u64, change: TimedChange) {
        if self.history(key, generation).is_none() {
            return;
        }
        let change = self.adopt(key, generation, change);
        self.insert_ordered(key, generation, vec![change]);
    }

    /// Sequence a change and make it the reference's baseline without
    /// queueing it (the builder's current-state fallback).
    pub(crate) fn adopt(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
        mut change: TimedChange,
    ) -> TimedChange {
        if let Some(history) = self.history_mut(key, generation) {
            history.baseline = Some(change.observation.clone());
        }
        change.seq = self.next_seq;
        self.next_seq += 1;
        change
    }

    /// Take every pending change of a live generation, oldest first.
    pub(crate) fn drain(&mut self, key: &CovSubscriptionKey, generation: u64) -> Vec<TimedChange> {
        let Some(history) = self.history_mut(key, generation) else {
            return Vec::new();
        };
        let drained: Vec<_> = history.entries.drain(..).collect();
        let bytes = drained.iter().map(|e| e.encoded_len).sum();
        self.release_bytes(key, bytes);
        drained
    }

    /// Record that changes up to `seq` were transmitted.
    fn commit(&mut self, key: &CovSubscriptionKey, generation: u64, seq: u64) {
        if let Some(history) = self.history_mut(key, generation) {
            history.committed = history.committed.max(seq);
        }
    }

    /// Return untransmitted changes to their reference in capture order. A
    /// replaced or removed generation discards them, and so does a newer
    /// transmitted change: delivering them now would regress the subscriber.
    fn requeue(&mut self, key: &CovSubscriptionKey, generation: u64, changes: Vec<TimedChange>) {
        let Some(history) = self.history(key, generation) else {
            return;
        };
        let committed = history.committed;
        let (keep, stale): (Vec<_>, Vec<_>) = changes
            .into_iter()
            .partition(|change| change.seq > committed);
        if !stale.is_empty() {
            self.dropped(key, stale.len(), "superseded by a transmitted newer change");
        }
        self.insert_ordered(key, generation, keep);
    }

    fn insert_ordered(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
        changes: Vec<TimedChange>,
    ) {
        let Some(history) = self.history_mut(key, generation) else {
            return;
        };
        let mut added = 0;
        for change in changes {
            added += change.encoded_len;
            let at = history.entries.partition_point(|e| e.seq < change.seq);
            history.entries.insert(at, change);
        }
        if let Some(context) = key.multiple_context() {
            *self.context_bytes.entry(context.clone()).or_default() += added;
        }
        self.enforce_bound(key);
    }

    fn enforce_bound(&mut self, key: &CovSubscriptionKey) {
        let Some(context) = key.multiple_context().cloned() else {
            return;
        };
        while self.context_bytes.get(&context).copied().unwrap_or(0) > self.capacity {
            // Only a change followed by a newer one of the same reference is
            // evictable: prefer this reference, then the oldest in the context.
            let evictable = |h: &TimedHistory| h.entries.len() > 1;
            let victim = if self.histories.get(key).is_some_and(evictable) {
                Some(key.clone())
            } else {
                self.histories
                    .iter()
                    .filter(|(k, h)| k.multiple_context() == Some(&context) && evictable(h))
                    .min_by_key(|(_, h)| h.entries[0].seq)
                    .map(|(k, _)| k.clone())
            };
            let Some(victim) = victim else {
                return;
            };
            let evicted = self
                .histories
                .get_mut(&victim)
                .and_then(|h| h.entries.pop_front())
                .expect("victim has an older pending change");
            self.release_bytes(&victim, evicted.encoded_len);
            self.dropped(&victim, 1, "context history full");
        }
    }

    fn dropped(&self, key: &CovSubscriptionKey, count: usize, reason: &str) {
        self.counters
            .timed_changes_dropped
            .fetch_add(count as u64, Ordering::Relaxed);
        warn!(
            object = ?key.object(),
            count,
            reason,
            "Dropped pending timestamped COV-multiple changes"
        );
    }

    fn release_bytes(&mut self, key: &CovSubscriptionKey, bytes: usize) {
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

    fn history(&self, key: &CovSubscriptionKey, generation: u64) -> Option<&TimedHistory> {
        self.histories
            .get(key)
            .filter(|h| h.generation == generation)
    }

    fn history_mut(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
    ) -> Option<&mut TimedHistory> {
        self.histories
            .get_mut(key)
            .filter(|h| h.generation == generation)
    }
}

/// Shared handle to the table's timestamped histories. Locked only for short
/// synchronous sections; never held across an await, and never while a
/// [`TimedClaim`] of the same store is dropped.
#[derive(Debug, Clone)]
pub(crate) struct TimedStore {
    histories: Arc<Mutex<TimedHistories>>,
    capacity: usize,
}

impl TimedStore {
    pub(super) fn new(max_apdu_length: usize, counters: Arc<AtomicCovCounters>) -> Self {
        let capacity = max_apdu_length.saturating_sub(ENVELOPE_RESERVE);
        Self {
            histories: Arc::new(Mutex::new(TimedHistories::new(capacity, counters))),
            capacity,
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, TimedHistories> {
        // A panic while holding this lock leaves only bounded queue state.
        self.histories
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Changes drained into one notification. Unless [`TimedClaim::commit`] is
/// called after the notification is transmitted, dropping the claim returns
/// the changes to their references.
#[derive(Debug)]
pub(crate) struct TimedClaim {
    store: TimedStore,
    changes: Vec<(CovSubscriptionKey, u64, Vec<TimedChange>)>,
}

impl TimedClaim {
    pub(crate) fn new(store: TimedStore) -> Self {
        Self {
            store,
            changes: Vec::new(),
        }
    }

    pub(crate) fn add(
        &mut self,
        key: CovSubscriptionKey,
        generation: u64,
        changes: Vec<TimedChange>,
    ) {
        if !changes.is_empty() {
            self.changes.push((key, generation, changes));
        }
    }

    /// Keep one notification's history within the context bound: discard the
    /// oldest change that some newer claimed change of its reference
    /// supersedes, until the claim fits. Latest changes are always kept.
    pub(crate) fn fit(&mut self) {
        loop {
            let used: usize = self
                .changes
                .iter()
                .flat_map(|(_, _, changes)| changes)
                .map(|change| change.encoded_len)
                .sum();
            if used <= self.store.capacity {
                return;
            }
            let Some(at) = self
                .changes
                .iter()
                .enumerate()
                .filter(|(_, (_, _, changes))| changes.len() > 1)
                .min_by_key(|(_, (_, _, changes))| changes[0].seq)
                .map(|(at, _)| at)
            else {
                return;
            };
            self.changes[at].2.remove(0);
            self.store
                .lock()
                .dropped(&self.changes[at].0, 1, "notification history full");
        }
    }

    /// The latest claimed change of a reference: its current conveyed state.
    pub(crate) fn latest(&self, key: &CovSubscriptionKey) -> Option<&TimedChange> {
        self.changes
            .iter()
            .find(|(k, _, _)| k == key)
            .and_then(|(_, _, changes)| changes.last())
    }

    /// Claimed changes that precede each reference's latest one, in capture
    /// order: queued history conveyed as distinct timestamped values.
    pub(crate) fn earlier(&self) -> Vec<(&CovSubscriptionKey, &TimedChange)> {
        let mut all: Vec<_> = self
            .changes
            .iter()
            .flat_map(|(key, _, changes)| {
                let earlier = &changes[..changes.len().saturating_sub(1)];
                earlier.iter().map(move |change| (key, change))
            })
            .collect();
        all.sort_by_key(|(_, change)| change.seq);
        all
    }

    /// Clock frame of the most recently captured claimed change.
    pub(crate) fn last_frame(&self) -> Option<ClockFrame> {
        self.changes
            .iter()
            .filter_map(|(_, _, changes)| changes.last())
            .max_by_key(|change| change.seq)
            .map(|change| change.frame)
    }

    /// The notification carrying these changes was transmitted: retire them.
    pub(crate) fn commit(mut self) {
        let mut store = self.store.lock();
        for (key, generation, changes) in self.changes.drain(..) {
            if let Some(last) = changes.last() {
                store.commit(&key, generation, last.seq);
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
        for (key, generation, changes) in self.changes.drain(..) {
            store.requeue(&key, generation, changes);
        }
    }
}

#[cfg(test)]
#[path = "timed_tests.rs"]
mod tests;
