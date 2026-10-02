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
//! Local bound policy: the pending changes of one COV-multiple context are
//! limited to an estimate of what one notification APDU of the local maximum
//! length can carry. The Standard expects additional notifications rather than
//! loss (§13.1, §13.18.1.1); until notifications are split, this bounds memory
//! by dropping instead, a documented deviation. On overflow the oldest change
//! of the same reference is evicted first, then the oldest change in the
//! context. A reference's newest change is never evicted, so every reference's
//! current state is always conveyed. Each discarded change is counted in
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

/// Octets reserved for the notification envelope and item framing when
/// deriving the per-context pending bound from the local maximum APDU.
const ENVELOPE_RESERVE: usize = 64;
/// Estimated framing per value: property identifier, optional index, value
/// open/close tags and the context-tagged Time_Of_Change.
const VALUE_FRAMING: usize = 16;
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

/// Encoded value of a reference's own coordinate, with the sequence and clock
/// frame of the change that set it.
#[derive(Debug, Clone)]
struct FieldRecord {
    value: Vec<u8>,
    seq: u64,
    frame: ClockFrame,
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
    /// The newest known value of the reference's own coordinate and when it
    /// changed, kept once delivered: what an explicit timestamped selector
    /// reports for its field in a round it conveys no change in (#987).
    field: Option<FieldRecord>,
    /// Sequence of the newest captured or conveyed change.
    latest: u64,
    /// Sequence of the newest delivered change. An older change returned by
    /// a failed notification would contradict what was already delivered.
    committed: u64,
    /// The context's Max_Notification_Delay, as last admitted.
    delay: Duration,
    entries: VecDeque<TimedChange>,
}

/// The encoded value `values` carry for the reference's own coordinate.
fn own_value(key: &CovSubscriptionKey, values: &[COVNotificationValue]) -> Option<Vec<u8>> {
    let CovSubscriptionKey::Multiple {
        property, index, ..
    } = key
    else {
        return None;
    };
    values
        .iter()
        .find(|value| {
            value.property_identifier == *property && value.property_array_index == *index
        })
        .map(|value| value.value.clone())
}

/// How [`TimedHistories::field_time`] times a carried field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldTiming {
    /// The reference is no longer live: the field is an ordinary value.
    NotLive,
    /// No time belongs to this value: leave the field out.
    NoTime,
    /// The capture sequence and clock frame of the change that set it.
    At(u64, ClockFrame),
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
    capacity: usize,
    counters: Arc<AtomicCovCounters>,
}

impl TimedHistories {
    fn new(capacity: usize, counters: Arc<AtomicCovCounters>) -> Self {
        Self {
            histories: HashMap::new(),
            context_bytes: HashMap::new(),
            not_before: HashMap::new(),
            wake: Arc::default(),
            next_seq: 1,
            next_incarnation: 1,
            capacity,
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
        let history = self
            .histories
            .entry(key.clone())
            .or_insert_with(|| TimedHistory {
                incarnation,
                generation,
                baseline: None,
                field: None,
                latest: 0,
                committed: 0,
                delay,
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

    /// How to time the own field of a timestamped reference that conveys no
    /// change now, carried by a sibling with the encoded `value` (#987).
    ///
    /// A reference that is no longer live (cancelled or renewed since its
    /// fanout looked) owns nothing: the field goes out as an ordinary sibling
    /// value. The value the reference last saw keeps that change's time: a
    /// capture records the own value whether or not it qualified, an admission
    /// or renewal capture included. Any other value changed without a capture
    /// (no producer recorded it): it takes `now()`, the preparation time,
    /// which is remembered for that value so a later notification carrying it
    /// reports the same time; the reference's baseline, and so its increment,
    /// is untouched. Without a time, because the clock is invalid or because a
    /// producer snapshot may be older than the record, the field has none to
    /// give.
    pub(crate) fn field_time(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
        value: &[u8],
        now: impl FnOnce() -> Option<ClockFrame>,
    ) -> FieldTiming {
        let seq = self.next_seq;
        let Some(history) = self.history_mut(key, generation) else {
            return FieldTiming::NotLive;
        };
        if let Some(field) = history.field.as_ref().filter(|field| field.value == value) {
            return FieldTiming::At(field.seq, field.frame);
        }
        let Some(frame) = now() else {
            return FieldTiming::NoTime;
        };
        history.field = Some(FieldRecord {
            value: value.to_vec(),
            seq,
            frame,
        });
        self.next_seq += 1;
        FieldTiming::At(seq, frame)
    }

    /// Record the own-field value a capture saw although it did not qualify
    /// (it moved less than the reference's increment), at `frame`, the time of
    /// the commit, so a sibling carrying it reports when it really changed.
    pub(crate) fn note_field(
        &mut self,
        key: &CovSubscriptionKey,
        generation: u64,
        values: &[COVNotificationValue],
        frame: ClockFrame,
    ) {
        let seq = self.next_seq;
        let (Some(history), Some(value)) =
            (self.history_mut(key, generation), own_value(key, values))
        else {
            return;
        };
        if history
            .field
            .as_ref()
            .is_some_and(|field| field.value == value)
        {
            return;
        }
        history.field = Some(FieldRecord { value, seq, frame });
        self.next_seq += 1;
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
            history.field = own_value(key, &change.values).map(|value| FieldRecord {
                value,
                seq: change.seq,
                frame: change.frame,
            });
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
        let capacity = max_apdu_length.saturating_sub(ENVELOPE_RESERVE);
        Self {
            histories: Arc::new(Mutex::new(TimedHistories::new(capacity, counters))),
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
        incarnation: u64,
        changes: Vec<TimedChange>,
    ) {
        if !changes.is_empty() {
            self.changes.push((key, incarnation, changes));
        }
    }

    /// Discard the oldest claimed change that a newer claimed change of its
    /// reference supersedes, so a notification fits its APDU. `false` when
    /// only each reference's latest change remains.
    pub(crate) fn drop_oldest_earlier(&mut self) -> bool {
        let Some(at) = self
            .changes
            .iter()
            .enumerate()
            .filter(|(_, (_, _, changes))| changes.len() > 1)
            .min_by_key(|(_, (_, _, changes))| changes[0].seq)
            .map(|(at, _)| at)
        else {
            return false;
        };
        self.changes[at].2.remove(0);
        self.store.lock().dropped(
            &self.changes[at].0,
            1,
            "notification exceeds the maximum APDU",
        );
        true
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
            store.requeue(&key, incarnation, changes);
        }
    }
}

#[cfg(test)]
#[path = "timed_tests.rs"]
mod tests;
