//! The COV fanout a background commit owes, sent after its guard is dropped.
use super::*;
use crate::committed_cov::CommittedCov;

/// Shared handles for fanning COV out from a background task (#889). It uses
/// the write path's post-commit fanout, so the ordering, budget and DCC rules
/// are the same as for a network write.
pub(super) struct CovFanout<T: TransportPort + 'static> {
    pub(super) db: Arc<RwLock<ObjectDatabase>>,
    pub(super) cov_table: Arc<RwLock<CovSubscriptionTable>>,
    network: Arc<NetworkLayer<T>>,
    cov_in_flight: Arc<Semaphore>,
    notification_transactions: Arc<NotificationTransactions>,
    comm_state: Arc<AtomicU8>,
    config: Arc<ServerConfig>,
}

impl<T: TransportPort + 'static> Clone for CovFanout<T> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            cov_table: Arc::clone(&self.cov_table),
            network: Arc::clone(&self.network),
            cov_in_flight: Arc::clone(&self.cov_in_flight),
            notification_transactions: Arc::clone(&self.notification_transactions),
            comm_state: Arc::clone(&self.comm_state),
            config: Arc::clone(&self.config),
        }
    }
}

impl<T: TransportPort + 'static> CovFanout<T> {
    pub(super) fn new(
        db: &Arc<RwLock<ObjectDatabase>>,
        network: &Arc<NetworkLayer<T>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        cov_in_flight: &Arc<Semaphore>,
        notification_transactions: &Arc<NotificationTransactions>,
        comm_state: &Arc<AtomicU8>,
        config: &ServerConfig,
    ) -> Self {
        Self {
            db: Arc::clone(db),
            cov_table: Arc::clone(cov_table),
            network: Arc::clone(network),
            cov_in_flight: Arc::clone(cov_in_flight),
            notification_transactions: Arc::clone(notification_transactions),
            comm_state: Arc::clone(comm_state),
            config: Arc::new(config.clone()),
        }
    }

    pub(super) async fn fire(&self, committed: &CommittedCov) {
        if committed.is_empty() {
            return;
        }
        BACnetServer::<T>::fire_post_write_cov_notifications(
            &self.db,
            &self.network,
            &self.cov_table,
            &self.cov_in_flight,
            &self.notification_transactions,
            &self.comm_state,
            &self.config,
            &committed.coarse,
            &committed.life_safety,
        )
        .await;
    }
}
