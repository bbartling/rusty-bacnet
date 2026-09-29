//! Capture of timestamped COV-multiple changes at the mutation boundary.
//!
//! Producers capture while still holding the database write guard that
//! committed the change, so each captured value is paired with the Device
//! clock frame of the commit rather than the later time of notification
//! preparation. The affected references are collected under a short COV
//! table read; object reads then run without the table guard, and the timed
//! store is locked last (database, then table, then timed store).
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::primitives::ObjectIdentifier;

use super::multiple_reads::MultipleReads;
use super::timed::{TimedChange, TimedStore};
use super::{CovNotificationKind, CovSubscriptionSnapshot, CovSubscriptionTable};

/// Live timestamped references whose changes a producer must capture.
pub(crate) struct TimedCapture {
    store: TimedStore,
    refs: Vec<CovSubscriptionSnapshot>,
    force: bool,
}

impl CovSubscriptionTable {
    /// References of `oid` a committing mutation must capture. Producers
    /// without capture (WritePropertyMultiple, staging writes, the Life Safety
    /// path) still report through the builder's current-state fallback,
    /// stamped when the notification is prepared.
    pub(crate) fn timed_capture(&self, oid: ObjectIdentifier) -> TimedCapture {
        // Life Safety fanout reports exact changed properties through its own
        // path; its references keep preparation-time stamping for now.
        let refs = if crate::life_safety_cov::is_life_safety_object(oid) {
            Vec::new()
        } else {
            self.subs
                .values()
                .filter(|sub| {
                    sub.monitored_object_identifier == oid
                        && sub.timestamped
                        && sub.notification_kind == CovNotificationKind::Multiple
                        && self.is_current(sub)
                })
                .cloned()
                .collect()
        };
        TimedCapture {
            store: self.timed.clone(),
            refs,
            force: false,
        }
    }

    /// Initial reports of newly (re)subscribed timestamped references. No
    /// change has been observed yet, so the local convention stamps the
    /// current value with the Device time of admission.
    pub(crate) fn initial_timed_capture(
        &self,
        snapshots: &[CovSubscriptionSnapshot],
    ) -> TimedCapture {
        TimedCapture {
            store: self.timed.clone(),
            refs: snapshots
                .iter()
                .filter(|sub| sub.timestamped && self.is_current(sub))
                .cloned()
                .collect(),
            force: true,
        }
    }
}

impl TimedCapture {
    /// Queue each qualifying change under the committing mutation's database
    /// guard. A missing or invalid Device clock captures nothing; the
    /// notification builder then applies its clockless policy.
    pub(crate) fn run(self, db: &ObjectDatabase) {
        if self.refs.is_empty() {
            return;
        }
        let Some(frame) = db
            .clock_frame()
            .filter(|frame| frame.is_valid_actual_datetime())
        else {
            return;
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
            timed.push(
                key,
                generation,
                TimedChange::new(frame, values, prepared.observation),
            );
        }
    }
}
