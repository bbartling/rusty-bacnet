//! Periodic intrinsic notification owner; uses the server's effective raw acceptance.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run<T: TransportPort + 'static>(
    db_intrinsic: Arc<RwLock<ObjectDatabase>>,
    network_intrinsic: Arc<NetworkLayer<T>>,
    comm_state_intrinsic: Arc<AtomicU8>,
    learned_routers_intrinsic: Arc<Mutex<LearnedRouterCache>>,
    notification_transactions_intrinsic: Arc<NotificationTransactions>,
    device_bindings_intrinsic: Arc<RwLock<DeviceBindingTable>>,
    intrinsic_retry_ms: u64,
    intrinsic_apdu_capacity: u32,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    // The countdown decrements exactly once per call, so a delayed wake
    // must NOT burst-deliver missed ticks (each would decrement
    // `remaining`, compressing the Time_Delay). `Delay` collapses a
    // missed deadline into a single tick, preserving per-second
    // granularity (ASHRAE 135-2020 §13.2.4).
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        // DCC gates the outbound sender, not event-state detection or
        // the local transition actions in Clause 13.2.2.1.4.
        // Collect resolved transitions under a brief write lock, then
        // drop it before sending (never hold the db lock across a
        // network send — matches the per-write notification path).
        //
        // Event_Enable gates distribution only (Clause 12.12), so every
        // proposal is committed locally before a suppressed
        // transition is omitted from the outbound work list.
        let fired = {
            let mut db = db_intrinsic.write().await;
            let mut out = Vec::new();
            for oid in db.list_objects() {
                let outcome = db
                    .get_mut(&oid)
                    .and_then(|object| object.tick_intrinsic_reporting());
                let resolved = outcome.and_then(|outcome| {
                    BACnetServer::<T>::commit_intrinsic_transition(&mut db, &oid, outcome)
                });
                if let Some(resolved) = resolved {
                    if resolved.distribute && resolved.event_values.is_some() {
                        out.push((oid, resolved));
                    }
                }
            }
            out
        };
        for (oid, resolved) in fired {
            BACnetServer::<T>::build_and_send_event_notification_with_bindings(
                &db_intrinsic,
                &network_intrinsic,
                &comm_state_intrinsic,
                &learned_routers_intrinsic,
                &notification_transactions_intrinsic,
                &device_bindings_intrinsic,
                &oid,
                resolved,
                intrinsic_retry_ms,
                intrinsic_apdu_capacity,
            )
            .await;
        }
    }
}
