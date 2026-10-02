//! Schedule execution engine.
//!
//! Periodically evaluates Schedule objects (Clause 12.24.4) against one Device
//! clock frame and writes the effective value to every controlled
//! object-property reference at the Schedule's Priority_For_Writing. A write
//! that commits to a Schedule runs the same evaluation for that Schedule at
//! once, since a change to what it holds can change its value (#1057).

use std::collections::HashMap;
use std::sync::Arc;

use crate::committed_cov::{BackgroundCommit, CommittedCov};
use crate::cov::CovSubscriptionTable;
use bacnet_objects::clock::ClockFrame;
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::calendar::SpecificDate;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, Time};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// The local date and time a clock frame gives schedule evaluation, or `None`
/// when the frame's date is not a real day or its time is not specific.
pub(crate) fn schedule_instant(frame: ClockFrame) -> Option<(SpecificDate, Time)> {
    let today = SpecificDate::from_date(&frame.local_date)?;
    frame
        .local_time
        .is_specific()
        .then_some((today, frame.local_time))
}

/// Evaluate all Schedule objects and write to their controlled properties.
///
/// A running server evaluates schedules itself every 60 seconds and fans COV
/// out for the objects they write; this entry point only evaluates.
pub async fn tick_schedules(db: &Arc<RwLock<ObjectDatabase>>) {
    let mut db_w = db.write().await;
    let schedules = db_w.find_by_type(ObjectType::SCHEDULE);
    evaluate(&mut db_w, schedules);
}

/// Evaluate schedules for the live server, returning the COV fanout owed for
/// the objects they wrote once the database guard is dropped.
pub(crate) async fn tick_schedules_committed(
    db: &Arc<RwLock<ObjectDatabase>>,
    cov_table: &RwLock<CovSubscriptionTable>,
) -> CommittedCov {
    let mut db_w = db.write().await;
    let schedules = db_w.find_by_type(ObjectType::SCHEDULE);
    let commit = evaluate(&mut db_w, schedules);
    commit.finish(&db_w, cov_table).await
}

/// Evaluate the Schedules among `written`, objects a write just committed to,
/// under the guard that committed it; returns the COV fanout owed for the
/// objects they wrote once that guard is dropped.
///
/// This is the pass [`tick_schedules_committed`] runs, limited to those
/// Schedules, so the new contents take effect without waiting for the next
/// tick. Lock order: the caller's database guard, then the COV table.
pub(crate) async fn reevaluate_written(
    db_w: &mut ObjectDatabase,
    written: &[ObjectIdentifier],
    cov_table: &RwLock<CovSubscriptionTable>,
) -> CommittedCov {
    let schedules: Vec<_> = written
        .iter()
        .copied()
        .filter(|oid| oid.object_type() == ObjectType::SCHEDULE)
        .collect();
    if schedules.is_empty() {
        return CommittedCov::default();
    }
    let commit = evaluate(db_w, schedules);
    commit.finish(db_w, cov_table).await
}

/// Whether each Calendar is TRUE on `today`, resolved once per pass so every
/// Schedule that references one sees the same answer.
fn calendar_states(db: &ObjectDatabase, today: SpecificDate) -> HashMap<ObjectIdentifier, bool> {
    db.find_by_type(ObjectType::CALENDAR)
        .into_iter()
        .filter_map(|oid| {
            let calendar = db.get(&oid)?;
            // A Calendar that does not evaluate a date list itself reports
            // its state through Present_Value.
            let active = calendar.calendar_state_internal(today).unwrap_or_else(|| {
                matches!(
                    calendar.read_property(PropertyIdentifier::PRESENT_VALUE, None),
                    Ok(PropertyValue::Boolean(true))
                )
            });
            Some((oid, active))
        })
        .collect()
}

fn evaluate(db_w: &mut ObjectDatabase, schedules: Vec<ObjectIdentifier>) -> BackgroundCommit {
    let mut commit = BackgroundCommit::new();
    let Some((today, now)) = db_w.clock_frame().and_then(schedule_instant) else {
        debug!("Skipping Schedule evaluation without a valid Device clock");
        return commit;
    };
    let calendars = calendar_states(db_w, today);
    let calendar_active = |oid: ObjectIdentifier| calendars.get(&oid).copied().unwrap_or(false);

    let mut writes = Vec::new();
    for oid in schedules {
        if let Some(obj) = db_w.get_mut(&oid) {
            if let Some(write) = obj.tick_schedule(today, now, &calendar_active) {
                debug!(
                    schedule = %oid,
                    refs = write.references.len(),
                    "Schedule value changed, writing to controlled properties"
                );
                writes.push((oid, write));
            }
        }
    }

    for (initiator, write) in writes {
        let origin = crate::command_source::resolve_local(
            db_w,
            crate::LocalCommandSource::Object(initiator),
        )
        .ok();
        // Clause 12.24.4: a failed member does not stop the others.
        for reference in write.references {
            let target_oid = reference.object_identifier;
            let prop_id = reference.property_identifier;
            commit.before_change(db_w, target_oid);
            if let Some(target_obj) = db_w.get_mut(&target_oid) {
                let prop = PropertyIdentifier::from_raw(prop_id);
                if let Err(e) = crate::command_source::write_target(
                    target_obj,
                    prop,
                    reference.property_array_index,
                    write.value.clone(),
                    Some(write.priority),
                    origin.as_ref(),
                ) {
                    warn!(
                        target = %target_oid,
                        property = prop_id,
                        error = %e,
                        "Schedule failed to write to controlled property"
                    );
                } else {
                    commit.changed(target_oid);
                }
            }
        }
    }
    commit
}

#[cfg(test)]
#[path = "schedule_tests.rs"]
pub(crate) mod tests;
