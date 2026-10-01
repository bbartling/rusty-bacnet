//! Capture of timestamped COV-multiple changes at the mutation boundary.
//!
//! Producers capture while still holding the database write guard that
//! committed the change, so each captured value is paired with the Device
//! clock frame of the commit rather than the later time of notification
//! preparation. Producers collect the affected references under a short COV
//! table read and read objects after releasing it; the admission capture runs
//! inside the subscribe handler, which already holds the table. The timed
//! store is always locked last (database, then table, then timed store).
//!
//! Ordinary objects capture by each reference's reporting criterion. Life
//! Safety objects report exactly the properties a mutation changed, so they
//! capture through [`CovSubscriptionTable::timed_capture_exact`] with the same
//! selection as their exact fanout. WritePropertyMultiple captures every
//! successful attempt as it commits, through [`TimedWriteCapture`].
use bacnet_objects::clock::ClockFrame;
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};

use super::multiple_reads::MultipleReads;
use super::timed::{TimedChange, TimedStore};
use super::{CovNotificationKind, CovSubscriptionSnapshot, CovSubscriptionTable};
use crate::handlers::{WriteCommitObserver, WriteTarget};
use crate::life_safety_cov::{is_life_safety_object, LifeSafetyCovChange, LifeSafetyCovSnapshots};

/// Live timestamped references whose changes a producer must capture.
#[derive(Clone)]
pub(crate) struct TimedCapture {
    store: TimedStore,
    refs: Vec<CovSubscriptionSnapshot>,
    force: bool,
    /// Device clock sample the caller already validated, instead of a read.
    frame: Option<ClockFrame>,
}

/// Whether a Life Safety exact change selects `sub`, as the exact fanout
/// does: its property changed, or Status_Flags did.
fn exact_selects(sub: &CovSubscriptionSnapshot, change: &LifeSafetyCovChange) -> bool {
    sub.monitored_object_identifier == change.object_identifier
        && (change
            .changed_properties
            .contains(&PropertyIdentifier::STATUS_FLAGS)
            || sub
                .monitored_property
                .is_some_and(|property| change.changed_properties.contains(&property)))
}

impl CovSubscriptionTable {
    fn timed_refs(&self, select: impl Fn(&CovSubscriptionSnapshot) -> bool) -> TimedCapture {
        TimedCapture {
            store: self.timed.clone(),
            refs: self
                .subs
                .values()
                .filter(|sub| {
                    sub.timestamped
                        && sub.notification_kind == CovNotificationKind::Multiple
                        && select(sub)
                        && self.is_current(sub)
                })
                .cloned()
                .collect(),
            force: false,
            frame: None,
        }
    }

    /// References of `oid` an ordinary committing mutation must capture. A
    /// Life Safety object captures its exact changes instead.
    pub(crate) fn timed_capture(&self, oid: ObjectIdentifier) -> TimedCapture {
        let ordinary = !is_life_safety_object(oid);
        self.timed_refs(|sub| ordinary && sub.monitored_object_identifier == oid)
    }

    /// References the exact Life Safety fanout of `changes` reports: Life
    /// Safety mutations, and LifeSafetyOperation changes on any object.
    pub(crate) fn timed_capture_exact(&self, changes: &[LifeSafetyCovChange]) -> TimedCapture {
        self.timed_refs(|sub| changes.iter().any(|change| exact_selects(sub, change)))
    }

    /// Every live timestamped reference, for a producer that commits several
    /// objects one after another under one guard.
    pub(crate) fn timed_capture_all(&self) -> TimedCapture {
        self.timed_refs(|_| true)
    }

    /// Initial reports of newly (re)subscribed timestamped references. No
    /// change has been observed yet, so the local convention stamps the
    /// current value with the Device time of admission: `frame`, the sample
    /// the admission check validated.
    pub(crate) fn initial_timed_capture(
        &self,
        snapshots: &[CovSubscriptionSnapshot],
        frame: ClockFrame,
    ) -> TimedCapture {
        TimedCapture {
            store: self.timed.clone(),
            refs: snapshots
                .iter()
                .filter(|sub| sub.timestamped && self.is_current(sub))
                .cloned()
                .collect(),
            force: true,
            frame: Some(frame),
        }
    }
}

impl TimedCapture {
    fn select(&self, keep: impl Fn(&CovSubscriptionSnapshot) -> bool) -> Self {
        Self {
            refs: self.refs.iter().filter(|sub| keep(sub)).cloned().collect(),
            ..self.clone()
        }
    }

    /// The ordinary references of one written object.
    fn object(&self, oid: ObjectIdentifier) -> Self {
        let ordinary = !is_life_safety_object(oid);
        self.select(|sub| ordinary && sub.monitored_object_identifier == oid)
    }

    /// The references one Life Safety exact change selects.
    fn exact(&self, change: &LifeSafetyCovChange) -> Self {
        self.select(|sub| exact_selects(sub, change))
    }

    fn watches(&self, oid: ObjectIdentifier) -> bool {
        self.refs
            .iter()
            .any(|sub| sub.monitored_object_identifier == oid)
    }

    /// Queue each qualifying change under the committing mutation's database
    /// guard, and report whether any was queued. A missing or invalid Device
    /// clock captures nothing; the notification builder then applies its
    /// clockless policy.
    pub(crate) fn run(self, db: &ObjectDatabase) -> bool {
        if self.refs.is_empty() {
            return false;
        }
        let Some(frame) = self.frame.or_else(|| {
            db.clock_frame()
                .filter(|frame| frame.is_valid_actual_datetime())
        }) else {
            return false;
        };
        let mut reads = MultipleReads::default();
        for sub in &self.refs {
            if let Some(object) = db.get(&sub.monitored_object_identifier) {
                reads.capture_source(object, sub);
            }
        }
        let current: Vec<_> = self
            .refs
            .iter()
            .filter_map(|sub| {
                let object = db.get(&sub.monitored_object_identifier)?;
                Some((sub, reads.read(object, sub)?))
            })
            .collect();
        let mut timed = self.store.lock();
        let mut queued = false;
        for (sub, prepared) in current {
            let key = sub.key();
            let generation = sub.generation();
            let baseline = timed
                .baseline(key, generation)
                .or(sub.last_notified_observation.as_ref())
                .cloned();
            if !self.force && !reads.reports(&prepared, baseline.as_ref()) {
                continue;
            }
            let values =
                reads.with_flags_companion(&sub.monitored_object_identifier, prepared.values);
            queued |= timed.push(
                key,
                generation,
                TimedChange::new(frame, values, prepared.observation),
            );
        }
        queued
    }
}

/// Per-attempt capture for a write request, composed around its Audit
/// observer. Each successful attempt is captured as it commits, under the
/// request's database guard, so a WritePropertyMultiple that goes A-B-A, or
/// fails after a committed prefix, conveys every change it made. A Life
/// Safety object captures the exact changes of that one attempt.
pub(crate) struct TimedWriteCapture<'a> {
    inner: Option<&'a mut dyn WriteCommitObserver>,
    capture: TimedCapture,
    /// State of the Life Safety object the current attempt writes, from
    /// before the attempt.
    life_safety: Option<LifeSafetyCovSnapshots>,
    /// Life Safety objects with changes captured by some attempt.
    life_safety_captured: Vec<ObjectIdentifier>,
}

impl<'a> TimedWriteCapture<'a> {
    pub(crate) fn new(
        capture: TimedCapture,
        inner: Option<&'a mut dyn WriteCommitObserver>,
    ) -> Self {
        Self {
            inner,
            capture,
            life_safety: None,
            life_safety_captured: Vec::new(),
        }
    }

    /// Life Safety objects whose attempts queued timestamped changes but which
    /// have no change in the request's `exact` changes. Those compare the end
    /// of the request with its start, so an object written out and back has
    /// nothing to fan out there. Its ordinary fanout conveys the captured
    /// changes; its untimestamped references find no change against their
    /// baselines.
    pub(crate) fn life_safety_without_exact_change(
        &self,
        exact: &[LifeSafetyCovChange],
    ) -> Vec<ObjectIdentifier> {
        self.life_safety_captured
            .iter()
            .copied()
            .filter(|oid| !exact.iter().any(|change| change.object_identifier == *oid))
            .collect()
    }
}

impl WriteCommitObserver for TimedWriteCapture<'_> {
    fn before(&mut self, db: &ObjectDatabase, write: WriteTarget<'_>) {
        self.life_safety = (is_life_safety_object(write.oid) && self.capture.watches(write.oid))
            .then(|| LifeSafetyCovSnapshots::capture_oid(db, write.oid));
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.before(db, write);
        }
    }

    fn commit_policy(
        &mut self,
        db: &mut ObjectDatabase,
        write: WriteTarget<'_>,
        value: &PropertyValue,
    ) -> Option<Result<(), Error>> {
        self.inner.as_deref_mut()?.commit_policy(db, write, value)
    }

    fn committed(&mut self, db: &mut ObjectDatabase) {
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.committed(db);
        }
    }

    fn failed(&mut self, db: &mut ObjectDatabase, error: &Error) {
        self.life_safety = None;
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.failed(db, error);
        }
    }

    fn applied(&mut self, db: &ObjectDatabase, oid: ObjectIdentifier) {
        if let Some(inner) = self.inner.as_deref_mut() {
            inner.applied(db, oid);
        }
        if !is_life_safety_object(oid) {
            self.capture.object(oid).run(db);
            return;
        }
        if let Some(before) = self.life_safety.take() {
            for change in before.changes(db, std::slice::from_ref(&oid)) {
                if self.capture.exact(&change).run(db) && !self.life_safety_captured.contains(&oid)
                {
                    self.life_safety_captured.push(oid);
                }
            }
        }
    }
}
