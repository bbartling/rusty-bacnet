//! The second half of a local write: what it owes once the object holds the
//! value (#1367).
//!
//! [`LocalWriter::commit`] makes the write under a database guard it keeps
//! and hands that guard on in a [`Committed`]. [`LocalWriter::finish`] then
//! takes the timestamped COV capture and re-evaluates a written Schedule
//! under that same guard, releases it, and runs the event pass, the COV
//! fanout, the fanout for a re-evaluated Schedule's targets and any Staging
//! plan. `write_local` runs `finish` as a task of its own in the server's
//! request task set, so a caller that drops its future (a timeout, a
//! `select!`, a cancelled Python task) no longer skips any of it.

use super::local_writes::LocalWriter;
use super::*;
use crate::command_lists::TakenRuns;
use crate::life_safety_cov::LifeSafetyCovChange;
use bacnet_objects::staging::StagingWritePlan;
use tokio::sync::OwnedRwLockWriteGuard;

/// A local write that has committed, with what it still owes.
pub(in crate::server) struct Committed {
    /// The guard the write committed under, still held. First, so that
    /// dropping a `Committed` frees the database before `command_runs` ends
    /// its runs in it.
    pub(super) db: OwnedRwLockWriteGuard<ObjectDatabase>,
    /// The written object.
    pub(super) oid: ObjectIdentifier,
    /// Whether it is a Life Safety object, whose COV path reports exactly
    /// the properties that changed.
    pub(super) life_safety: bool,
    /// The Life Safety properties the write changed.
    pub(super) changes: Vec<LifeSafetyCovChange>,
    /// The Staging plan the write queued, if any.
    pub(super) staging_plans: Vec<StagingWritePlan>,
    /// The Command and Channel runs the write queued.
    pub(super) command_runs: TakenRuns,
}

impl<T: TransportPort + 'static> LocalWriter<'_, T> {
    /// Do what `committed` owes, and return the runs it queued, those of a
    /// Schedule it re-evaluated included, for the caller to start.
    pub(in crate::server) async fn finish(&self, committed: Committed) -> TakenRuns {
        let Committed {
            mut db,
            oid,
            life_safety,
            changes,
            staging_plans,
            mut command_runs,
        } = committed;
        // Under the write's guard: the database, then the COV table.
        let capture = {
            let table = self.cov_table.read().await;
            if life_safety {
                table.timed_capture_exact(&changes)
            } else {
                table.timed_capture(oid)
            }
        };
        capture.run(&db);
        let schedule_cov = crate::schedule::reevaluate_written(
            self.db,
            &mut db,
            std::slice::from_ref(&oid),
            self.cov_table,
        )
        .await;
        drop(db);

        BACnetServer::<T>::fire_event_notifications_with_bindings(
            &self.event_delivery(),
            self.cov_table,
            &oid,
        )
        .await;
        if life_safety {
            for change in changes {
                BACnetServer::<T>::fire_life_safety_cov_notifications(
                    &self.cov_context(),
                    &change.object_identifier,
                    &change.changed_properties,
                )
                .await;
            }
        } else {
            BACnetServer::<T>::fire_cov_notifications(&self.cov_context(), &oid).await;
        }
        // Targets a written Schedule commanded on re-evaluation.
        BACnetServer::<T>::fire_post_write_cov_notifications(
            &self.cov_context(),
            &schedule_cov.coarse,
            &schedule_cov.life_safety,
        )
        .await;
        command_runs.extend(schedule_cov.command_runs);
        BACnetServer::<T>::execute_staging_plans(
            &self.event_delivery(),
            &self.cov_context(),
            staging_plans,
        )
        .await;
        command_runs
    }
}
