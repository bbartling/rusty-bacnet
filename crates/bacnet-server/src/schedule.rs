//! Schedule execution engine.
//!
//! Periodically evaluates Schedule objects and writes the effective value
//! to all controlled object-property references.

use std::sync::Arc;

use crate::committed_cov::{BackgroundCommit, CommittedCov};
use crate::cov::CovSubscriptionTable;
use bacnet_objects::clock::ClockFrame;
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Compute the weekly-schedule index and time from one shared clock frame.
pub(crate) fn current_time_components(frame: ClockFrame) -> Option<(u8, u8, u8)> {
    let day_of_week = frame.local_date.day_of_week.checked_sub(1)?;
    (day_of_week <= 6).then_some((day_of_week, frame.local_time.hour, frame.local_time.minute))
}

/// Evaluate all Schedule objects and write to their controlled properties.
///
/// A running server evaluates schedules itself every 60 seconds and fans COV
/// out for the objects they write; this entry point only evaluates.
pub async fn tick_schedules(db: &Arc<RwLock<ObjectDatabase>>) {
    evaluate(&mut *db.write().await);
}

/// Evaluate schedules for the live server, returning the COV fanout owed for
/// the objects they wrote once the database guard is dropped.
pub(crate) async fn tick_schedules_committed(
    db: &Arc<RwLock<ObjectDatabase>>,
    cov_table: &RwLock<CovSubscriptionTable>,
) -> CommittedCov {
    let mut db_w = db.write().await;
    let commit = evaluate(&mut db_w);
    commit.finish(&db_w, cov_table).await
}

fn evaluate(db_w: &mut ObjectDatabase) -> BackgroundCommit {
    let mut commit = BackgroundCommit::begin(db_w);
    let Some((day_of_week, hour, minute)) = db_w.clock_frame().and_then(current_time_components)
    else {
        debug!("Skipping Schedule evaluation without a valid Device clock");
        return commit;
    };

    let mut writes = Vec::new();
    for oid in db_w.find_by_type(ObjectType::SCHEDULE) {
        if let Some(obj) = db_w.get_mut(&oid) {
            if let Some((value, refs)) = obj.tick_schedule(day_of_week, hour, minute) {
                debug!(
                    schedule = %oid,
                    refs = refs.len(),
                    "Schedule value changed, writing to controlled properties"
                );
                for reference in refs {
                    writes.push((oid, reference, value.clone()));
                }
            }
        }
    }

    for (initiator, reference, value) in writes {
        let origin = crate::command_source::resolve_local(
            db_w,
            crate::LocalCommandSource::Object(initiator),
        )
        .ok();
        let target_oid = reference.object_identifier;
        let prop_id = reference.property_identifier;
        if let Some(target_obj) = db_w.get_mut(&target_oid) {
            let prop = PropertyIdentifier::from_raw(prop_id);
            if let Err(e) = crate::command_source::write_target(
                target_obj,
                prop,
                reference.property_array_index,
                value,
                None,
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
    commit
}
