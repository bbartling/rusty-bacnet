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
    /// Call it before dropping the server. A server dropped without it in
    /// async code aborts its tasks and lets the object database go on Tokio's
    /// blocking pool once they have let go of it (#1409), so the drop returns
    /// at once, but nothing waits for the objects' last saves.
    ///
    /// Once its requests are joined, a write a Notification Forwarder,
    /// Notification Class or Audit Log still holds staged for one of them is
    /// dropped, and stop waits until every save those objects have queued
    /// has run, so storage holds the state each object serves (#1363); see
    /// [`DurableWrites::settle_forgotten_writes`]. That wait has no limit:
    /// storage that stalls holds stop up, and a warning naming the objects
    /// still saving is logged after 5 s and every 30 s after that. Stop does
    /// not wait while the application holds the database: the objects then
    /// settle once it lets go, and put storage back when they are dropped.
    ///
    /// [`DurableWrites::settle_forgotten_writes`]: bacnet_objects::durable::DurableWrites::settle_forgotten_writes
    ///
    /// Cancelling this waiter leaves cleanup owned by the server. A later stop
    /// joins it; after transport cleanup begins, dropping the server lets that
    /// cleanup finish. Local mutation and broadcasts are rejected from the first
    /// stop poll; local reads and database inspection remain available.
    pub async fn stop(&mut self) -> Result<(), Error> {
        if let Some(network) = &self.network {
            network.seal_responses();
        }
        self.broadcaster.seal();
        self.request_tasks.close();
        stop_producer(&mut self.network_number_task).await;
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
                &self.cov_revisit_task,
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
        stop_producer(&mut self.cov_revisit_task).await;
        // No request is left to take or release a staged save, and the
        // operation task that would drop one is gone: put storage back to
        // what each object serves before stop returns (#1363). A
        // `write_local` still in flight isn't joined; if it staged, it finds
        // its stage gone and saves in place under the guard.
        super::durable_writes::settle_forgotten(&self.db).await;
        // Nothing can own a Command or Channel run any more. End the runs let
        // go of while the database was busy where they stood, then any run no
        // task took up, so none is left in progress (#1252). An application
        // holding the database doesn't hold up stop: they end once it's free.
        crate::command_lists::end_unowned(&self.db, self.request_tasks.take_stranded());
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
        if let Some(network) = &self.network {
            network.seal_responses();
        }
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
        let mut tasks: Vec<JoinHandle<()>> = [
            &mut self.dispatch_task,
            &mut self.network_number_task,
            &mut self.cov_purge_task,
            &mut self.fault_detection_task,
            &mut self.event_enrollment_task,
            &mut self.trend_log_task,
            &mut self.schedule_tick_task,
            &mut self.intrinsic_reporting_task,
            &mut self.binary_lighting_operation_task,
            &mut self.cov_revisit_task,
        ]
        .into_iter()
        .filter_map(Option::take)
        .collect();
        if let Ok(mut timer) = self.dcc_timer.try_lock() {
            tasks.extend(timer.take());
        }
        for task in &tasks {
            task.abort();
        }
        self.let_database_go(tasks);
    }
}

impl<T: TransportPort> BACnetServer<T> {
    /// Let the object database go off the async runtime as the server is
    /// dropped (#1409).
    ///
    /// Dropping the database drops its objects, and a durable object waits
    /// for the saves it has queued, after putting storage back to the state
    /// it serves when a write is still staged (#1363). A server dropped in
    /// async code without `stop()` would block a Tokio worker for as long as
    /// storage takes. So when a runtime is current, the server's handle goes
    /// to a task that waits until `tasks`, aborted, and the server's request
    /// and notification tasks have let go of theirs; then, if nothing else
    /// holds the database, it is dropped on the blocking pool, as DeleteObject
    /// drops a removed object. An application still holding the database
    /// drops the last handle itself. With no runtime current, the database
    /// drops here, as it always has.
    fn let_database_go(&mut self, tasks: Vec<JoinHandle<()>>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let db = std::mem::take(&mut self.db);
        let requests = Arc::clone(&self.request_tasks);
        let notifications = Arc::clone(&self.notification_transactions);
        runtime.spawn(async move {
            for task in tasks {
                let _ = task.await;
            }
            while let Some(result) = requests.join_next().await {
                super::request_tasks::RequestTasks::observe(Some(result));
            }
            while let Some(result) = notifications.join_next().await {
                NotificationTransactions::observe(Some(result));
            }
            if Arc::strong_count(&db) == 1 {
                drop(tokio::task::spawn_blocking(move || drop(db)));
            }
        });
    }
}
