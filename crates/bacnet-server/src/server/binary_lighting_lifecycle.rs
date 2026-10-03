use super::cov_fanout::CovFanout;
use super::*;
use crate::committed_cov::BackgroundCommit;
use tokio::time::{Instant, MissedTickBehavior};

/// Spawn the task that drives every object's monotonic operation deadlines.
///
/// It is generic over objects: each wake first takes the Averaging samples
/// that are due (#1144), then asks every object to expire what is due
/// (`advance_monotonic_time_internal`) and to report its next deadline, and
/// fans COV out for each object that changed once the database guard is
/// dropped. Binary Lighting Output egress, Access Door pulse relock (#1073)
/// and Averaging sampling all run on it; the name predates the other two.
pub(super) fn spawn_binary_lighting_operation_task<T: TransportPort + 'static>(
    fanout: CovFanout<T>,
    monotonic_origin: Instant,
) -> JoinHandle<()> {
    let owner = fanout.notification_transactions.audit_owner_lease();
    super::heap_futures::spawn_boxed(move || async move {
        let _owner = owner;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut next_deadline = None;
        loop {
            if let Some(deadline) = next_deadline {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = tokio::time::sleep_until(monotonic_origin + deadline) => {}
                }
            } else {
                interval.tick().await;
            }
            let now = Instant::now().saturating_duration_since(monotonic_origin);

            let (changed, sampled) = {
                let mut database = fanout.db.write().await;
                // Sampling first steps each due schedule, so the deadlines
                // gathered below are the next ones. The samples fan out as a
                // background commit, like a schedule write.
                let mut sampled = BackgroundCommit::new();
                for oid in database.sample_due_averaging_objects(now) {
                    sampled.changed(oid);
                }
                let mut changed = Vec::new();
                next_deadline = None;
                database.for_each_object_mut(|oid, object| {
                    if object.advance_monotonic_time_internal(now) {
                        if let Some(snapshot) = object.cov_snapshot_internal() {
                            changed.push((oid, snapshot));
                        }
                    }
                    if let Some(deadline) = object.next_monotonic_deadline_internal() {
                        next_deadline =
                            Some(next_deadline.map_or(deadline, |next| next.min(deadline)));
                    }
                });
                // A deadline this pass left due would wake the task at once,
                // over and over, without letting paused or real time move on;
                // look at it again a millisecond later instead.
                next_deadline = next_deadline
                    .map(|deadline: Duration| deadline.max(now + Duration::from_millis(1)));
                if !changed.is_empty() {
                    let captures: Vec<_> = {
                        let table = fanout.cov_table.read().await;
                        changed
                            .iter()
                            .map(|(oid, _)| table.timed_capture(*oid))
                            .collect()
                    };
                    for capture in captures {
                        capture.run(&database);
                    }
                }
                let sampled = sampled
                    .finish(&fanout.db, &mut database, &fanout.cov_table)
                    .await;
                (changed, sampled)
            };

            fanout.fire(&sampled).await;
            for (oid, snapshot) in changed {
                BACnetServer::<T>::fire_cov_notifications_from_snapshot(
                    &fanout.notify_context(),
                    &oid,
                    snapshot.as_ref(),
                )
                .await;
            }
        }
    })
}
