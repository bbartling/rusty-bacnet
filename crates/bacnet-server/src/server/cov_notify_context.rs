//! Borrowed handles shared by the COV notification entry points.
use super::*;

/// The server handles a COV notification pass reads: object database,
/// network, subscription table, in-flight permits, notification transactions,
/// the DCC communication state and the server config.
pub(super) struct CovNotifyContext<'a, T: TransportPort + 'static> {
    pub(super) db: &'a Arc<RwLock<ObjectDatabase>>,
    pub(super) network: &'a Arc<NetworkLayer<T>>,
    pub(super) cov_table: &'a Arc<RwLock<CovSubscriptionTable>>,
    pub(super) cov_in_flight: &'a Arc<Semaphore>,
    pub(super) notification_transactions: &'a Arc<NotificationTransactions>,
    pub(super) comm_state: &'a Arc<AtomicU8>,
    pub(super) config: &'a ServerConfig,
}
