//! Event notifications to a Device recipient the server holds no fresh
//! binding for (#1368).
//!
//! Such a recipient used to be skipped, and counted in
//! `device_recipient_unbound`. Now the server looks for its device through
//! the binding table's probes ([`DeviceLookup`]), as a Command or Channel
//! write in another device does (#1322): one Who-Is limited to the device's
//! instance, at most one a minute per device, shared by everything that
//! misses while it is out, and none while DeviceCommunicationControl
//! restricts initiation.
//!
//! The notification waits for the I-Am, for the probe's bounded wait, the
//! APDU timeout from the Who-Is. A notification's recipients are served one
//! after another, so the wait is not made there: the recipients still
//! waiting go to one task of their own in the notification task set, which
//! waits on their probes together and then sends to each recipient whose
//! device answered, along the same path as every other recipient
//! ([`BACnetServer::send_on_route`]). The notification's other recipients,
//! and the caller, never wait for it, and `stop()` aborts the task with the
//! other notification workers.
//!
//! The counters stay as they were for one destination: a recipient whose
//! device stays silent counts once in `device_recipient_unbound`, as does
//! one that can't be looked for (within the hold-off of a fruitless Who-Is,
//! or with too many devices being looked for), and a notification sent
//! after the I-Am counts as any other send does. Nothing is counted for one
//! DCC holds back.

use super::super::binding_probes::{
    can_look_for, DeviceLookup, LookupMiss, LookupStart, ProbeWait,
};
use super::super::device_bindings::DeviceResolution;
use super::*;

/// How a Device recipient's route is found.
pub(super) enum DeviceRoute {
    /// Its binding, or the lack of one, as the table holds it now.
    Now(DeviceResolution),
    /// A Who-Is for its device is out: the notification waits for the I-Am.
    Awaited(ProbeWait),
    /// DCC restricts initiation: no Who-Is, and nothing sent or counted.
    Withheld,
}

/// A Device recipient whose notification waits for its device's I-Am.
pub(super) struct Awaited {
    pub(super) device: ObjectIdentifier,
    pub(super) process_id: u32,
    pub(super) confirmed: bool,
    pub(super) wait: ProbeWait,
}

/// The handles an awaited notification's task owns, for an
/// [`EventDelivery`] once its devices have answered.
struct OwnedDelivery<T: TransportPort + 'static> {
    db: Arc<RwLock<ObjectDatabase>>,
    network: Arc<NetworkLayer<T>>,
    comm_state: Arc<CommState>,
    learned_routers: Arc<Mutex<LearnedRouterCache>>,
    notification_transactions: Arc<NotificationTransactions>,
    device_bindings: Arc<RwLock<DeviceBindingTable>>,
    suppressions: Arc<super::super::event_suppression::EventSuppressions>,
    retry_timeout_ms: u64,
    local_apdu_capacity: u32,
}

impl<T: TransportPort + 'static> OwnedDelivery<T> {
    fn of(ctx: &EventDelivery<'_, T>) -> Self {
        Self {
            db: Arc::clone(ctx.db),
            network: Arc::clone(ctx.network),
            comm_state: Arc::clone(ctx.comm_state),
            learned_routers: Arc::clone(ctx.learned_routers),
            notification_transactions: Arc::clone(ctx.notification_transactions),
            device_bindings: Arc::clone(ctx.device_bindings),
            suppressions: Arc::clone(ctx.suppressions),
            retry_timeout_ms: ctx.retry_timeout_ms,
            local_apdu_capacity: ctx.local_apdu_capacity,
        }
    }

    fn delivery(&self) -> EventDelivery<'_, T> {
        EventDelivery {
            db: &self.db,
            network: &self.network,
            comm_state: &self.comm_state,
            learned_routers: &self.learned_routers,
            notification_transactions: &self.notification_transactions,
            device_bindings: &self.device_bindings,
            suppressions: &self.suppressions,
            retry_timeout_ms: self.retry_timeout_ms,
            local_apdu_capacity: self.local_apdu_capacity,
        }
    }
}

/// The probes of the server `ctx` is, with the APDU timeout as their wait.
fn lookup<'a, T: TransportPort + 'static>(ctx: &EventDelivery<'a, T>) -> DeviceLookup<'a, T> {
    DeviceLookup {
        network: ctx.network,
        bindings: ctx.device_bindings,
        comm_state: ctx.comm_state,
        wait: Duration::from_millis(ctx.retry_timeout_ms),
    }
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// The route to Device `device`: its binding, or a Who-Is for it when
    /// the server holds none fresh. A device that can't be looked for keeps
    /// the resolution it has, which the send path skips and counts.
    pub(super) async fn device_route(
        ctx: &EventDelivery<'_, T>,
        device: ObjectIdentifier,
    ) -> DeviceRoute {
        let lookup = lookup(ctx);
        let resolution = lookup.resolve(device).await;
        if !can_look_for(device, &resolution) {
            return DeviceRoute::Now(resolution);
        }
        match lookup.start(device).await {
            LookupStart::Resolved(resolution) => DeviceRoute::Now(resolution),
            LookupStart::Waiting(wait) => DeviceRoute::Awaited(wait),
            LookupStart::NotLooking => DeviceRoute::Now(resolution),
            LookupStart::Disabled => DeviceRoute::Withheld,
        }
    }

    /// Hand the recipients still waiting for their devices' I-Am to one task
    /// in the notification task set: it waits on their probes together, then
    /// sends `outbound` to each recipient whose device answered and counts
    /// each one whose device stayed silent once.
    pub(super) fn send_when_found(
        ctx: &EventDelivery<'_, T>,
        outbound: &OutboundNotification<'_>,
        awaited: Vec<Awaited>,
    ) {
        let mut waits = Vec::with_capacity(awaited.len());
        let mut pending = Vec::with_capacity(awaited.len());
        for Awaited {
            device,
            process_id,
            confirmed,
            wait,
        } in awaited
        {
            // As on the send path: the request is encoded once a recipient
            // is known, and encoding can't fail for a committed transition.
            match (outbound.encode_for)(process_id) {
                Ok(bytes) => {
                    waits.push(wait);
                    pending.push((device, process_id, confirmed, bytes));
                }
                Err(e) => warn!(error = %e, "Failed to encode EventNotification"),
            }
        }
        if pending.is_empty() {
            return;
        }
        let owned = OwnedDelivery::of(ctx);
        let (notification_class, priority) = (outbound.notification_class, outbound.priority);
        let admits = Arc::clone(&outbound.admits);
        let budget = outbound.budget.clone();
        ctx.notification_transactions.spawn(async move {
            // The probes are waited on together, and no lock is taken until
            // every wait is over (#1494).
            futures_util::future::join_all(waits.into_iter().map(ProbeWait::answered)).await;
            let ctx = owned.delivery();
            let lookup = lookup(&ctx);
            for (device, process_id, confirmed, bytes) in pending {
                if ctx.comm_state.initiation_restricted() {
                    return;
                }
                match lookup.found(device).await {
                    Ok(resolution) => {
                        let network = ctx.network;
                        let route = RecipientRoute::from_device_resolution(resolution).localize(
                            network.local_network_number().get(),
                            |mac| network.transport().is_broadcast_mac(mac),
                            |mac| network.transport().is_group_destination(mac),
                        );
                        let encode_for = |_| Ok(bytes.clone());
                        let outbound = OutboundNotification {
                            notification_class,
                            priority,
                            encode_for: &encode_for,
                            admits: Arc::clone(&admits),
                            budget: budget.clone(),
                        };
                        Self::send_on_route(&ctx, &outbound, route, process_id, confirmed).await;
                    }
                    Err(LookupMiss::Undiscovered) => {
                        ctx.suppressions
                            .record(EventSuppression::DeviceRecipientUnbound);
                        warn!(
                            notification_class,
                            %device,
                            "Skipping Device recipient: its device didn't answer a Who-Is"
                        );
                    }
                    Err(LookupMiss::Disabled) => {}
                }
            }
        });
    }
}

#[cfg(test)]
#[path = "event_awaited_recipients_tests.rs"]
mod tests;
