//! Retained timestamped COV-multiple changes (135-2020 §13.16.3.1.2.3, §13.17.1.1).
//!
//! A reference subscribed with `Timestamped=TRUE` must report every qualifying
//! change with the local time it happened, and keep those changes until a
//! notification carrying them is sent. Producers capture each change under
//! the database write guard; the notification builder drains the queue into a
//! [`TimedClaim`] that requeues its entries unless the notification was
//! delivered: transmitted when unconfirmed, acknowledged when confirmed. Keeping
//! a confirmed report's changes until its Ack is local policy (#896).
//!
//! Changes are normally reported as soon as they are captured. A change stays
//! queued when its notification fails or is held back: a failed send, an
//! unanswered confirmed report, DISABLE_INITIATION, an exhausted budget. The
//! context's Max_Notification_Delay, an upper bound, then limits the wait,
//! measured from its earliest queued change (§13.1, §13.16.1.1.4):
//! [`TimedStore::next_due`] hands the server each context whose deadline has
//! passed, and the server fans it out again.
//!
//! Local policy for that backstop:
//! - it acts no sooner than one second after the earliest change;
//! - after an attempt it waits the delay (one second at least) before the
//!   next one, so a persistent failure cannot spin;
//! - a confirmed hold-off moves the next attempt to the end of the hold-off,
//!   and an outstanding confirmed report leaves the follow-up to its outcome;
//! - [`TimedStore::rearm`] drops every wait when a block lifts
//!   (communication re-enabled, a shorter delay admitted), so overdue changes
//!   go out at once.
//!
//! Delays and waits live only with timestamped histories, so a context
//! without one costs nothing here.
//!
//! History that one notification cannot carry goes out in several (§13.1,
//! §13.18.1.1): [`TimedClaim::split_earliest`] moves the oldest history into
//! earlier notifications, and each reference's latest change stays with the
//! last one.
//!
//! Local bound policy: the pending changes of one COV-multiple context are
//! limited to an estimate of what [`HISTORY_NOTIFICATIONS`] notifications can
//! carry, each of the smaller of the local maximum APDU and the subscriber's.
//! The estimate counts each change's values, item framing as if every change
//! started its own item, and a reserve for the context's untimestamped values,
//! which travel with the last notification. Peers therefore cannot grow this
//! state without limit. Only on overflow, the last resort, is a change dropped:
//! the oldest of the same reference first, then the oldest in the context. A
//! reference's newest change is never evicted, so every reference's current
//! state is always conveyed. Each discarded change is counted in
//! [`AtomicCovCounters::timed_changes_dropped`].

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bacnet_objects::clock::ClockFrame;
use bacnet_services::cov_multiple::COVNotificationValue;
use tokio::sync::Notify;
use tokio::time::Instant;
use tracing::warn;

use super::{AtomicCovCounters, CovObservation, CovSubscriptionKey, MultipleContextKey};

/// Notifications' worth of pending history one context may hold.
pub(crate) const HISTORY_NOTIFICATIONS: usize = 4;
/// Most octets a COV-multiple notification spends outside its items: the
/// unsegmented confirmed request header (4), process identifier (5), device
/// identifier (5), time remaining (5), the date and time envelope (12) and the
/// list's opening and closing tags (2).
const ENVELOPE_RESERVE: usize = 33;
/// Octets of one item's framing: its context-tagged object identifier (5) and
/// the opening and closing tags of its value list (2).
pub(crate) const ITEM_FRAMING: usize = 7;
/// Earliest the deadline backstop acts after a change, and the least spacing
/// between its attempts on one blocked context.
const DEADLINE_FLOOR: Duration = Duration::from_secs(1);

/// One captured change of a timestamped reference, ready to be conveyed.
#[derive(Debug, Clone)]
pub(crate) struct TimedChange {
    seq: u64,
    frame: ClockFrame,
    /// Monotonic instant of the capture: the Max_Notification_Delay origin,
    /// unaffected by later Device clock adjustments.
    captured_at: Instant,
    values: Vec<COVNotificationValue>,
    observation: CovObservation,
    encoded_len: usize,
}

/// Octets of a context-tagged unsigned value: its tag and the minimal
/// big-endian content, one octet at least.
fn unsigned_len(value: u64) -> usize {
    1 + (1..8)
        .find(|octets| value >> (8 * octets) == 0)
        .unwrap_or(8)
}

/// Encoded octets of one entry of a COV-multiple value list: its property
/// identifier, optional array index, the value between its opening and closing
/// tags, and its Time_Of_Change when present.
pub(crate) fn value_len(value: &COVNotificationValue) -> usize {
    unsigned_len(u64::from(value.property_identifier.to_raw()))
        + value
            .property_array_index
            .map_or(0, |index| unsigned_len(u64::from(index)))
        + 2
        + value.value.len()
        + if value.time_of_change.is_some() { 5 } else { 0 }
}

impl TimedChange {
    /// Pair prepared values with the Device clock frame of the change. Every
    /// value carries the frame's local time as its Time_Of_Change.
    pub(crate) fn new(
        frame: ClockFrame,
        mut values: Vec<COVNotificationValue>,
        observation: CovObservation,
    ) -> Self {
        let mut encoded_len = ITEM_FRAMING;
        for value in &mut values {
            value.time_of_change = Some(frame.local_time);
            encoded_len += value_len(value);
        }
        Self {
            seq: 0,
            frame,
            captured_at: Instant::now(),
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
    /// Identity of this history across renewals. A cancelled and recreated
    /// reference gets a new one, so late returns cannot reach it.
    incarnation: u64,
    generation: u64,
    /// Latest observation already captured or conveyed; the next change
    /// qualifies against it rather than the last completed delivery.
    baseline: Option<CovObservation>,
    /// Sequence of the newest captured or conveyed change.
    latest: u64,
    /// Sequence of the newest delivered change. An older change returned by
    /// a failed notification would contradict what was already delivered.
    committed: u64,
    /// The context's Max_Notification_Delay, as last admitted.
    delay: Duration,
    /// Octets one notification to the context may take: the smaller of the
    /// local maximum APDU and the subscriber's, as last admitted.
    apdu: usize,
    /// Most octets the context's untimestamped values have taken in one of
    /// its reports since this history began.
    reserve: usize,
    entries: VecDeque<TimedChange>,
}

impl TimedHistory {
    /// Octets of pending changes the history's context may hold.
    fn capacity(&self) -> usize {
        (HISTORY_NOTIFICATIONS * self.apdu.saturating_sub(ENVELOPE_RESERVE))
            .saturating_sub(self.reserve)
    }
}

/// Pending timestamped changes of every live timestamped Multiple reference.
#[derive(Debug)]
pub(crate) struct TimedHistories {
    histories: HashMap<CovSubscriptionKey, TimedHistory>,
    context_bytes: HashMap<MultipleContextKey, usize>,
    /// Earliest the deadline backstop may hand a context out again. Only a
    /// context with a timestamped history has an entry.
    not_before: HashMap<MultipleContextKey, Instant>,
    /// Wakes [`TimedStore::next_due`] when a deadline may have moved earlier.
    wake: Arc<Notify>,
    next_seq: u64,
    next_incarnation: u64,
    /// Local maximum APDU length.
    local_apdu: usize,
    counters: Arc<AtomicCovCounters>,
}

impl TimedHistories {
    fn new(local_apdu: usize, counters: Arc<AtomicCovCounters>) -> Self {
        Self {
            histories: HashMap::new(),
            context_bytes: HashMap::new(),
            not_before: HashMap::new(),
            wake: Arc::default(),
            next_seq: 1,
            next_incarnation: 1,
            local_apdu,
            counters,
        }
    }

    /// Apply a context's admitted Max_Notification_Delay to its timestamped
    /// histories. Every admission of the context, renewals included, calls
    /// it; a context without one keeps nothing.
    pub(super) fn set_delay(&mut self, context: &MultipleContextKey, seconds: u32) {
        let delay = Duration::from_secs(u64::from(seconds));
        let mut shorter = false;
        for (key, history) in &mut self.histories {
            if key.multiple_context() == Some(context) {
                shorter |= delay < history.delay;
                history.delay = delay;
            }
        }
        if shorter {
            self.rearm_context(context);
        }
    }

    /// Apply the maximum APDU the context's subscriber last advertised, if
    /// known, to its timestamped histories: notifications and the history
    /// bound use the smaller of it and the local maximum.
    pub(super) fn set_apdu(&mut self, context: &MultipleContextKey, subscriber: Option<u16>) {
        let apdu = subscriber.map_or(self.local_apdu, |subscriber| {
            self.local_apdu.min(usize::from(subscriber))
        });
        for (key, history) in &mut self.histories {
            if key.multiple_context() == Some(context) {
                history.apdu = apdu;
            }
        }
    }

    /// Note the octets the context's untimestamped values took in a report.
    /// The history bound keeps room for the most they have taken, since they
    /// travel with the last notification of the next report too.
    pub(crate) fn note_reserve(&mut self, context: &MultipleContextKey, octets: usize) {
        for (key, history) in &mut self.histories {
            if key.multiple_context() == Some(context) {
                history.reserve = history.reserve.max(octets);
            }
        }
    }

    /// Drop every backstop wait: a block lifted, so overdue changes go out
    /// at the next scan.
    pub(crate) fn rearm(&mut self) {
        self.not_before.clear();
        self.wake.notify_one();
    }

    /// A shorter delay moves the context's deadline earlier: drop its wait
    /// and wake the backstop to recompute.
    fn rearm_context(&mut self, context: &MultipleContextKey) {
        self.not_before.remove(context);
        self.wake.notify_one();
    }

    /// A confirmed hold-off blocks `context` until `until`: the backstop's
    /// next attempt waits for exactly that, not for its usual spacing.
    pub(crate) fn hold_until(&mut self, context: &MultipleContextKey, until: Instant) {
        if self
            .histories
            .keys()
            .any(|key| key.multiple_context() == Some(context))
        {
            self.not_before.insert(context.clone(), until);
            self.wake.notify_one();
        }
    }

    /// Take the references with pending changes of every context whose
    /// deadline has passed at `now`, and the next deadline still ahead.
    ///
    /// A context is due at its earliest pending change plus its delay, but no
    /// sooner than [`DEADLINE_FLOOR`] after that change, nor before its wait
    /// from a previous attempt or hold-off. Handing it out starts a wait of its
    /// delay (the floor at least), in case the attempt is blocked again.
    pub(crate) fn take_due(&mut self, now: Instant) -> (Vec<CovSubscriptionKey>, Option<Instant>) {
        // Earliest pending change and shortest delay per context.
        let mut pending: HashMap<&MultipleContextKey, (Instant, Duration)> = HashMap::new();
        for (key, history) in &self.histories {
            let (Some(context), Some(first)) = (key.multiple_context(), history.entries.front())
            else {
                continue;
            };
            pending
                .entry(context)
                .and_modify(|(at, delay)| {
                    *at = (*at).min(first.captured_at);
                    *delay = (*delay).min(history.delay);
                })
                .or_insert((first.captured_at, history.delay));
        }
        let mut due = Vec::new();
        let mut next: Option<Instant> = None;
        for (&context, &(first, delay)) in &pending {
            let spacing = delay.max(DEADLINE_FLOOR);
            let mut deadline = first + spacing;
            if let Some(&wait) = self.not_before.get(context) {
                deadline = deadline.max(wait);
            }
            if deadline <= now {
                due.push((context.clone(), spacing));
            } else {
                next = Some(next.map_or(deadline, |at| at.min(deadline)));
            }
        }
        self.not_before
            .retain(|context, _| pending.contains_key(context));
        for (context, spacing) in &due {
            self.not_before.insert(context.clone(), now + *spacing);
        }
        let due: Vec<_> = due.into_iter().map(|(context, _)| context).collect();
        let keys = self
            .histories
            .iter()
            .filter(|(key, history)| {
                !history.entries.is_empty()
                    && key
                        .multiple_context()
                        .is_some_and(|context| due.contains(context))
            })
            .map(|(key, _)| key.clone())
            .collect();
        (keys, next)
    }

    /// Bind a (re)published reference generation with its context's admitted
    /// Max_Notification_Delay in seconds. A renewal keeps changes not yet
    /// conveyed; its initial report is captured afresh.
    pub(super) fn reset(&mut self, key: &CovSubscriptionKey, generation: u64, delay: u32) {
        let delay = Duration::from_secs(u64::from(delay));
        let incarnation = self.next_incarnation;
        let apdu = self.local_apdu;
        let history = self
            .histories
            .entry(key.clone())
            .or_insert_with(|| TimedHistory {
                incarnation,
                generation,
                baseline: None,
                latest: 0,
                committed: 0,
                delay,
                apdu,
                reserve: 0,
                entries: VecDeque::new(),
            });
        if history.incarnation == incarnation {
            self.next_incarnation += 1;
        }
        let shorter = delay < history.delay;
        history.generation = generation;
        history.baseline = None;
        history.delay = delay;
        if let Some(context) = key.multiple_context().filter(|_| shorter) {
            self.rearm_context(context);
        }
    }

    /// Drop the history of a removed reference, and its context's backstop
    /// wait once no timestamped reference of the context remains.
    pub(super) fn remove(&mut self, key: &CovSubscriptionKey) {
        if let Some(history) = self.histories.remove(key) {
            let bytes: usize = history.entries.iter().map(|e| e.encoded_len).sum();
            self.release_bytes(key, bytes);
        }
        if let Some(context) = key.multiple_context() {
            if !self
                .histories
                .keys()
                .any(|other| other.multiple_context() == Some(context))
            {
                self.not_before.remove(context);
            }
        }
    }

    /// Timestamped histories and backstop waits held, for leak tests.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        (self.histories.len(), self.not_before.len())
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
    /// older pending changes if the context bound is exceeded. Returns `false`
    /// when the generation is no longer live and nothing was queued.
    pub(crate) fn push(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
        change: TimedChange,
    ) -> bool {
        if self.history(key, generation).is_none() {
            return false;
        }
        let change = self.adopt(key, generation, change);
        self.insert_ordered(key, generation, vec![change]);
        true
    }

    /// Sequence a change and make it the reference's baseline without
    /// queueing it (the builder's current-state fallback).
    pub(crate) fn adopt(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
        mut change: TimedChange,
    ) -> TimedChange {
        change.seq = self.next_seq;
        self.next_seq += 1;
        if let Some(history) = self.history_mut(key, generation) {
            history.baseline = Some(change.observation.clone());
            history.latest = change.seq;
        }
        change
    }

    /// Take every pending change of a live generation, oldest first, with the
    /// history incarnation that later commits or returns them. Older changes
    /// returned by a failed notification stay queued while the reference's
    /// newest change is still in flight elsewhere, so they are never conveyed
    /// as its latest state; that change's outcome settles them.
    pub(crate) fn drain(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
    ) -> (u64, Vec<TimedChange>) {
        let Some(history) = self.history_mut(key, generation) else {
            return (0, Vec::new());
        };
        let incarnation = history.incarnation;
        if history
            .entries
            .back()
            .is_some_and(|newest| newest.seq < history.latest)
        {
            return (incarnation, Vec::new());
        }
        let drained: Vec<_> = history.entries.drain(..).collect();
        let bytes = drained.iter().map(|e| e.encoded_len).sum();
        self.release_bytes(key, bytes);
        (incarnation, drained)
    }

    /// Record that changes up to `seq` were delivered; queued older changes
    /// are superseded by it.
    fn commit(&mut self, key: &CovSubscriptionKey, incarnation: u64, seq: u64) {
        let Some(history) = self.incarnation_mut(key, incarnation) else {
            return;
        };
        history.committed = history.committed.max(seq);
        let committed = history.committed;
        let stale = history
            .entries
            .partition_point(|change| change.seq < committed);
        let removed: Vec<_> = history.entries.drain(..stale).collect();
        if !removed.is_empty() {
            let bytes = removed.iter().map(|change| change.encoded_len).sum();
            self.release_bytes(key, bytes);
            self.dropped(key, removed.len(), "superseded by a delivered newer change");
        }
    }

    /// Return undelivered changes to their reference in capture order, also
    /// across a renewal. A cancelled reference discards them, and a newer
    /// delivered change supersedes them: delivering them now would regress
    /// the subscriber.
    fn requeue(&mut self, key: &CovSubscriptionKey, incarnation: u64, changes: Vec<TimedChange>) {
        let Some(history) = self.incarnation_mut(key, incarnation) else {
            return;
        };
        let generation = history.generation;
        let committed = history.committed;
        let (keep, stale): (Vec<_>, Vec<_>) = changes
            .into_iter()
            .partition(|change| change.seq > committed);
        if !stale.is_empty() {
            self.dropped(key, stale.len(), "superseded by a delivered newer change");
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
        // A new oldest pending change can bring its context's deadline forward.
        let mut new_front = false;
        for change in changes {
            added += change.encoded_len;
            let at = history.entries.partition_point(|e| e.seq < change.seq);
            new_front |= at == 0;
            history.entries.insert(at, change);
        }
        if let Some(context) = key.multiple_context() {
            *self.context_bytes.entry(context.clone()).or_default() += added;
        }
        self.enforce_bound(key);
        if new_front {
            self.wake.notify_one();
        }
    }

    fn enforce_bound(&mut self, key: &CovSubscriptionKey) {
        let (Some(context), Some(capacity)) = (
            key.multiple_context().cloned(),
            self.histories.get(key).map(TimedHistory::capacity),
        ) else {
            return;
        };
        while self.context_bytes.get(&context).copied().unwrap_or(0) > capacity {
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

    fn incarnation_mut(
        &mut self,
        key: &CovSubscriptionKey,
        incarnation: u64,
    ) -> Option<&mut TimedHistory> {
        self.histories
            .get_mut(key)
            .filter(|h| h.incarnation == incarnation)
    }
}

/// Shared handle to the table's timestamped histories. Locked only for short
/// synchronous sections; never held across an await, and never while a
/// [`TimedClaim`] of the same store is dropped.
#[derive(Debug, Clone)]
pub(crate) struct TimedStore {
    histories: Arc<Mutex<TimedHistories>>,
}

impl TimedStore {
    pub(super) fn new(max_apdu_length: usize, counters: Arc<AtomicCovCounters>) -> Self {
        Self {
            histories: Arc::new(Mutex::new(TimedHistories::new(max_apdu_length, counters))),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, TimedHistories> {
        // A panic while holding this lock leaves only bounded queue state.
        self.histories
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Wait until some context's pending changes reach their deadline, and
    /// return that context's references with pending changes for the caller
    /// to fan out. A context that stays blocked comes back after its spacing.
    pub(crate) async fn next_due(&self) -> Vec<CovSubscriptionKey> {
        let wake = Arc::clone(&self.lock().wake);
        loop {
            let notified = wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (due, next) = self.lock().take_due(Instant::now());
            if !due.is_empty() {
                return due;
            }
            match next {
                Some(deadline) => {
                    tokio::select! {
                        () = tokio::time::sleep_until(deadline) => {}
                        () = notified => {}
                    }
                }
                None => notified.await,
            }
        }
    }

    /// A block on notifications lifted (communication re-enabled): overdue
    /// changes go out at the next scan instead of after a backstop wait.
    pub(crate) fn rearm(&self) {
        self.lock().rearm();
    }

    /// See [`TimedHistories::hold_until`].
    pub(crate) fn hold_until(&self, context: &MultipleContextKey, until: Instant) {
        self.lock().hold_until(context, until);
    }
}

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
}

impl TimedClaim {
    pub(crate) fn new(store: TimedStore) -> Self {
        Self {
            store,
            changes: Vec::new(),
            history_only: false,
        }
    }

    /// The store these changes return to.
    pub(crate) fn store(&self) -> &TimedStore {
        &self.store
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

    /// Clock frame of the most recently captured claimed change.
    pub(crate) fn last_frame(&self) -> Option<ClockFrame> {
        self.changes
            .iter()
            .filter_map(|(_, _, changes)| changes.last())
            .max_by_key(|change| change.seq)
            .map(|change| change.frame)
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
            store.requeue(&key, incarnation, changes);
        }
    }
}

#[cfg(test)]
#[path = "timed_tests.rs"]
mod tests;
