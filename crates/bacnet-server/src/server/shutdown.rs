use super::*;

#[cfg(test)]
#[path = "request_tasks_tests.rs"]
mod request_tasks_tests;

#[cfg(test)]
#[path = "producer_shutdown_tests.rs"]
mod producer_shutdown_tests;

#[cfg(test)]
#[path = "transport_shutdown_tests.rs"]
mod transport_shutdown_tests;

#[cfg(test)]
#[path = "owned_shutdown_tests.rs"]
mod owned_shutdown_tests;

async fn stop_producer(slot: &mut Option<JoinHandle<()>>) {
    // Borrow across the join so cancellation leaves the handle recoverable.
    // Clear synchronously after completion: a later stop must not poll it twice.
    if let Some(task) = slot.as_mut() {
        task.abort();
        let _ = task.await;
    }
    *slot = None;
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Seal egress, join admitted work, and stop the owned transport.
    ///
    /// Cancelling this waiter leaves cleanup owned by the server. A later stop
    /// joins it; after transport cleanup begins, dropping the server lets that
    /// cleanup finish. Local mutation and broadcasts are rejected from the first
    /// stop poll; local reads and database inspection remain available.
    pub async fn stop(&mut self) -> Result<(), Error> {
        self.broadcaster.seal();
        self.request_tasks.close();
        if let Some(runtime) = &self.target_audit {
            // Only the target drain retains ingress for ACK/control progress.
            self.notification_transactions
                .application_sealed
                .store(true, Ordering::Release);
            runtime.seal();
            runtime.batches.begin_stop();
            for task in [
                &self.fault_detection_task,
                &self.event_enrollment_task,
                &self.trend_log_task,
                &self.schedule_tick_task,
                &self.intrinsic_reporting_task,
                &self.binary_lighting_operation_task,
                &self.cov_purge_task,
            ]
            .into_iter()
            .flatten()
            {
                task.abort();
            }
            {
                let mut timer = self.dcc_timer.lock().await;
                super::dcc_timer::cancel(&mut timer).await;
            }
            loop {
                let finished = runtime.batches.finished.notified();
                tokio::pin!(finished);
                finished.as_mut().enable();
                if runtime.batches.stopped() {
                    break;
                }
                finished.await;
            }
        } else {
            // Other profiles retain their sequential, cancellation-safe shutdown.
            self.notification_transactions.close();
        }
        // Keep the handle in self until joined: cancellation must not detach
        // dispatch and allow a later stop to race its join consumer.
        if let Some(task) = self.dispatch_task.as_mut() {
            task.abort();
            let _ = task.await;
        }
        self.dispatch_task = None;
        while let Some(result) = self.request_tasks.join_next().await {
            super::request_tasks::RequestTasks::observe(Some(result));
        }
        {
            let mut timer = self.dcc_timer.lock().await;
            super::dcc_timer::cancel(&mut timer).await;
        }
        stop_producer(&mut self.fault_detection_task).await;
        stop_producer(&mut self.event_enrollment_task).await;
        stop_producer(&mut self.trend_log_task).await;
        stop_producer(&mut self.schedule_tick_task).await;
        stop_producer(&mut self.intrinsic_reporting_task).await;
        stop_producer(&mut self.binary_lighting_operation_task).await;
        stop_producer(&mut self.cov_purge_task).await;
        // Dispatch has relinquished the sole join-consumer role. Retain the
        // set in self across await so a cancelled stop can finish this drain.
        while let Some(result) = self.notification_transactions.join_next().await {
            NotificationTransactions::observe(Some(result));
        }
        if let Some(runtime) = &self.target_audit {
            runtime.uninstall(&mut *self.db.write().await);
        }
        self.target_audit = None;
        if let Some(error) = &self.transport_cleanup_error {
            return Err(Error::Encoding(error.clone()));
        }
        if self.transport_cleanup.is_none() {
            if let Some(network) = self.network.take() {
                let mut network = match Arc::try_unwrap(network) {
                    Ok(network) => network,
                    Err(network) => {
                        self.network = Some(network);
                        return Err(Error::Encoding(
                            "server network still has an internal owner".into(),
                        ));
                    }
                };
                // Own the complete future, including cancellation-unsafe custom
                // transport cleanup. Drop deliberately leaves this task running.
                self.transport_cleanup = Some(tokio::spawn(async move {
                    let result = network.stop().await;
                    (network, result)
                }));
            }
        }
        let Some(cleanup) = self.transport_cleanup.as_mut() else {
            return Ok(());
        };
        let outcome = cleanup.await;
        self.transport_cleanup = None;
        match outcome {
            Ok((network, result)) => {
                if result.is_err() {
                    self.network = Some(Arc::new(network));
                }
                result
            }
            Err(error) => {
                let message = format!("transport cleanup task failed: {error}");
                self.transport_cleanup_error = Some(message.clone());
                Err(Error::Encoding(message))
            }
        }
    }
}

impl<T: TransportPort> Drop for BACnetServer<T> {
    fn drop(&mut self) {
        self.broadcaster.seal();
        self.notification_transactions
            .application_sealed
            .store(true, Ordering::Release);
        if let Some(runtime) = &self.target_audit {
            runtime.seal();
            drop(runtime.batches.close());
        }
        self.request_tasks.close();
        self.notification_transactions.close();
        for task in [
            &self.dispatch_task,
            &self.cov_purge_task,
            &self.fault_detection_task,
            &self.event_enrollment_task,
            &self.trend_log_task,
            &self.schedule_tick_task,
            &self.intrinsic_reporting_task,
            &self.binary_lighting_operation_task,
        ]
        .into_iter()
        .flatten()
        {
            task.abort();
        }
        if let Ok(timer) = self.dcc_timer.try_lock() {
            if let Some(task) = timer.as_ref() {
                task.abort();
            }
        }
    }
}
