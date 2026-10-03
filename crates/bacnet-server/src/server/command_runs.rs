//! Running the action list a Command object's Present_Value write selects
//! (Clause 12.10, #1150).
//!
//! The write only queues the run: under the guard that commits it, the
//! Command object checks the number, sets In_Process and leaves a
//! [`CommandRun`] for the server to take (`take_command_runs`). Each run then
//! goes into the server's request task set as its own task, so neither the
//! request that wrote Present_Value nor `write_local` waits for it, post
//! delays included, and `stop` cancels it with the other request work.
//!
//! The commands are made one at a time, in list order, each through the
//! same [`LocalWriter`] path as `write_local`: priorities, command-source
//! tracking, audit, COV and the post-write event pass all apply as for any
//! other local write. No database guard is held across a write's
//! notifications or a post delay. A Command object's generation guards every
//! report back, so a run whose object was replaced or reconfigured stops.

use super::local_writes::{LocalWrite, LocalWriter};
use super::request_tasks::RequestTaskSpawner;
use super::*;
use bacnet_objects::command::CommandRun;
use bacnet_types::constructed::BACnetActionCommand;

/// The server handles a run owns while it waits out post delays.
pub(super) struct CommandRunner<T: TransportPort + 'static> {
    db: Arc<RwLock<ObjectDatabase>>,
    network: Arc<NetworkLayer<T>>,
    cov_table: Arc<RwLock<CovSubscriptionTable>>,
    cov_in_flight: Arc<Semaphore>,
    notification_transactions: Arc<NotificationTransactions>,
    comm_state: Arc<AtomicU8>,
    learned_routers: Arc<Mutex<LearnedRouterCache>>,
    device_bindings: Arc<RwLock<DeviceBindingTable>>,
    event_suppressions: Arc<super::event_suppression::EventSuppressions>,
    config: Arc<ServerConfig>,
    tasks: RequestTaskSpawner,
}

impl<T: TransportPort + 'static> Clone for CommandRunner<T> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            network: Arc::clone(&self.network),
            cov_table: Arc::clone(&self.cov_table),
            cov_in_flight: Arc::clone(&self.cov_in_flight),
            notification_transactions: Arc::clone(&self.notification_transactions),
            comm_state: Arc::clone(&self.comm_state),
            learned_routers: Arc::clone(&self.learned_routers),
            device_bindings: Arc::clone(&self.device_bindings),
            event_suppressions: Arc::clone(&self.event_suppressions),
            config: Arc::clone(&self.config),
            tasks: self.tasks.clone(),
        }
    }
}

impl<T: TransportPort + 'static> CommandRunner<T> {
    /// A runner over a request's handles, starting runs beside its task.
    pub(super) fn new(services: &RequestServices<T>, tasks: &RequestTaskSpawner) -> Self {
        Self {
            db: Arc::clone(&services.db),
            network: Arc::clone(&services.network),
            cov_table: Arc::clone(&services.cov_table),
            cov_in_flight: Arc::clone(&services.cov_in_flight),
            notification_transactions: Arc::clone(&services.notification_transactions),
            comm_state: Arc::clone(&services.comm_state),
            learned_routers: Arc::clone(&services.learned_routers),
            device_bindings: Arc::clone(&services.device_bindings),
            event_suppressions: Arc::clone(&services.event_suppressions),
            config: Arc::clone(&services.config),
            tasks: tasks.clone(),
        }
    }

    /// A runner over a running server's own handles, for `write_local`.
    pub(super) fn for_server(server: &BACnetServer<T>) -> Self {
        let writer = server.local_writer();
        Self {
            db: Arc::clone(writer.db),
            network: Arc::clone(writer.network),
            cov_table: Arc::clone(writer.cov_table),
            cov_in_flight: Arc::clone(writer.cov_in_flight),
            notification_transactions: Arc::clone(writer.notification_transactions),
            comm_state: Arc::clone(writer.comm_state),
            learned_routers: Arc::clone(writer.learned_routers),
            device_bindings: Arc::clone(writer.device_bindings),
            event_suppressions: Arc::clone(writer.event_suppressions),
            config: Arc::new(writer.config.clone()),
            tasks: server.request_tasks.spawner(),
        }
    }

    /// Start each run as its own task. A panic in a target's write path
    /// ends that run as failed rather than leaving its Command busy.
    pub(super) fn start(&self, runs: Vec<CommandRun>) {
        use futures_util::FutureExt;
        for run in runs {
            let runner = self.clone();
            self.tasks.spawn(async move {
                let (source, generation) = (run.source, run.generation);
                let execution = std::panic::AssertUnwindSafe(runner.execute(run));
                if execution.catch_unwind().await.is_err() {
                    warn!(command = %source, "Command run panicked; ending it as failed");
                    runner.complete(source, generation, false).await;
                }
            });
        }
    }

    fn writer(&self) -> LocalWriter<'_, T> {
        LocalWriter {
            db: &self.db,
            network: &self.network,
            cov_table: &self.cov_table,
            cov_in_flight: &self.cov_in_flight,
            notification_transactions: &self.notification_transactions,
            comm_state: &self.comm_state,
            learned_routers: &self.learned_routers,
            device_bindings: &self.device_bindings,
            event_suppressions: &self.event_suppressions,
            config: &self.config,
        }
    }

    /// Make the run's commands in order, then end it.
    async fn execute(&self, run: CommandRun) {
        let mut all_succeeded = true;
        for (index, command) in run.commands.iter().enumerate() {
            let Some(success) = self.make(&run, index, command).await else {
                // The Command changed under the run; whatever replaced it
                // owns In_Process now.
                return;
            };
            all_succeeded &= success;
            // Clause 12.10.8: the delay follows every attempt, failed or not,
            // and comes before the next write or the end of the run.
            if let Some(delay) = command.post_delay {
                tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
            }
            if !success && command.quit_on_failure {
                break;
            }
        }
        self.complete(run.source, run.generation, all_succeeded)
            .await;
    }

    /// Make command `index` and record its outcome. `None` once the run is
    /// stale.
    async fn make(
        &self,
        run: &CommandRun,
        index: usize,
        command: &BACnetActionCommand,
    ) -> Option<bool> {
        let local = {
            let db = self.db.read().await;
            if db
                .get(&run.source)
                .and_then(|object| object.command_generation_internal())
                != Some(run.generation)
            {
                return None;
            }
            // Clause 12.10.8 leaves writes to other devices optional. This
            // server makes local ones only, so a command naming another
            // Device fails like any refused write. Naming this Device is the
            // same as naming none.
            command
                .device_identifier
                .is_none_or(|device| crate::local_device::selected_device(&db) == Some(device))
        };
        let success = if local {
            self.write(run.source, command).await
        } else {
            debug!(
                command = %run.source,
                device = ?command.device_identifier,
                "Command list names another device; this server writes locally only"
            );
            false
        };
        let recorded = {
            let mut db = self.db.write().await;
            let recorded = db.get_mut(&run.source).is_some_and(|object| {
                object.record_command_write_internal(run.generation, index, success)
            });
            if recorded {
                let capture = self.cov_table.read().await.timed_capture(run.source);
                capture.run(&db);
            }
            recorded
        };
        if !recorded {
            return None;
        }
        BACnetServer::<T>::fire_cov_notifications(&self.writer().cov_context(), &run.source).await;
        Some(success)
    }

    /// Write one command's value through the local write path; whether it
    /// was accepted.
    async fn write(&self, source: ObjectIdentifier, command: &BACnetActionCommand) -> bool {
        // The value reaches the target as a WriteProperty carrying the same
        // octets would, so constructed values take the shape the object
        // expects.
        let mut encoded = BytesMut::new();
        let value = encode_property_value(&mut encoded, &command.property_value).and_then(|()| {
            handlers::decode_write_property_value(
                command.property_identifier,
                command.property_array_index,
                &encoded,
            )
        });
        let written = match value {
            Ok(value) => {
                self.writer()
                    .write(
                        &command.object_identifier,
                        LocalWrite::Property {
                            property: command.property_identifier,
                            array_index: command.property_array_index,
                            priority: command.priority,
                        },
                        value,
                        Some(crate::LocalCommandSource::Object(source)),
                    )
                    .await
            }
            Err(error) => Err(error),
        };
        match written {
            // A write that starts another Command's list starts that run too.
            Ok(runs) => {
                self.start(runs);
                true
            }
            Err(error) => {
                debug!(
                    command = %source,
                    target = %command.object_identifier,
                    property = ?command.property_identifier,
                    %error,
                    "Command write failed"
                );
                false
            }
        }
    }

    /// End a run: In_Process back to FALSE and All_Writes_Successful set,
    /// reported to property subscribers.
    async fn complete(&self, source: ObjectIdentifier, generation: u64, all_succeeded: bool) {
        let completed = {
            let mut db = self.db.write().await;
            let completed = db.get_mut(&source).is_some_and(|object| {
                object.complete_command_run_internal(generation, all_succeeded)
            });
            if completed {
                let capture = self.cov_table.read().await.timed_capture(source);
                capture.run(&db);
            }
            completed
        };
        if completed {
            BACnetServer::<T>::fire_cov_notifications(&self.writer().cov_context(), &source).await;
        }
    }
}
