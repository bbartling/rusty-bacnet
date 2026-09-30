//! The COV fanout a background commit owes, sent after its guard is dropped,
//! and the follow-up fanout an acknowledged confirmed report owes (#896).
use super::cov_notify_context::CovNotifyContext;
use super::event_delivery::EventDelivery;
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
    pub(super) notification_transactions: Arc<NotificationTransactions>,
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

    /// Borrow the handles a COV notification pass reads.
    pub(super) fn notify_context(&self) -> CovNotifyContext<'_, T> {
        CovNotifyContext {
            db: &self.db,
            network: &self.network,
            cov_table: &self.cov_table,
            cov_in_flight: &self.cov_in_flight,
            notification_transactions: &self.notification_transactions,
            comm_state: &self.comm_state,
            config: &self.config,
        }
    }

    /// Borrow the handles an EventNotification send reads. The retry timeout
    /// and APDU capacity come from the server config.
    pub(super) fn event_delivery<'a>(
        &'a self,
        learned_routers: &'a Arc<Mutex<LearnedRouterCache>>,
        device_bindings: &'a Arc<RwLock<DeviceBindingTable>>,
    ) -> EventDelivery<'a, T> {
        EventDelivery {
            db: &self.db,
            network: &self.network,
            comm_state: &self.comm_state,
            learned_routers,
            notification_transactions: &self.notification_transactions,
            device_bindings,
            retry_timeout_ms: self.config.cov_retry_timeout_ms,
            local_apdu_capacity: self.config.max_apdu_length,
        }
    }

    pub(super) async fn fire(&self, committed: &CommittedCov) {
        if committed.is_empty() {
            return;
        }
        BACnetServer::<T>::fire_post_write_cov_notifications(
            &self.notify_context(),
            &committed.coarse,
            &committed.life_safety,
        )
        .await;
    }

    /// Fan out again each reference whose confirmed report was acknowledged,
    /// so changes held back while it was outstanding reach the subscriber
    /// (#896). Runs until the server aborts it.
    pub(super) async fn run_revisits(self) {
        use futures_util::FutureExt;
        let revisits = Arc::clone(self.cov_table.read().await.revisits());
        loop {
            let keys = revisits.next().await;
            let ctx = self.notify_context();
            let batch = BACnetServer::<T>::fire_cov_revisits(&ctx, &keys);
            // A panic ends only this batch; later acknowledgments still follow up.
            if std::panic::AssertUnwindSafe(batch)
                .catch_unwind()
                .await
                .is_err()
            {
                warn!(
                    references = keys.len(),
                    "COV follow-up fanout panicked; those references report on their next fanout"
                );
            }
        }
    }
}
