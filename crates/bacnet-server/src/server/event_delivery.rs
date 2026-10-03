//! Borrowed handles shared by the EventNotification send paths.
use super::*;

/// The server handles and delivery settings an EventNotification send reads:
/// object database, network, DCC communication state, learned routers,
/// notification transactions, device bindings, the undelivered-notification
/// counters, the confirmed retry timeout and the local APDU capacity.
pub(super) struct EventDelivery<'a, T: TransportPort + 'static> {
    pub(super) db: &'a Arc<RwLock<ObjectDatabase>>,
    pub(super) network: &'a Arc<NetworkLayer<T>>,
    pub(super) comm_state: &'a Arc<AtomicU8>,
    pub(super) learned_routers: &'a Arc<Mutex<LearnedRouterCache>>,
    pub(super) notification_transactions: &'a Arc<NotificationTransactions>,
    pub(super) device_bindings: &'a Arc<RwLock<DeviceBindingTable>>,
    pub(super) suppressions: &'a Arc<super::event_suppression::EventSuppressions>,
    pub(super) retry_timeout_ms: u64,
    pub(super) local_apdu_capacity: u32,
}
