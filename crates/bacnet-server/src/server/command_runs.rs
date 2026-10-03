//! Running the writes a Command or Channel object's Present_Value write
//! queues (Clauses 12.10 and 12.53, #1150, #1151).
//!
//! The write only queues the run: under the guard that commits it, the object
//! checks the value, marks itself busy and leaves a [`CommandRun`], which the
//! server takes there and owns from then on (`crate::command_lists`). Each
//! run then goes into the server's request task set as its own task, so
//! neither the request that wrote Present_Value nor `write_local` waits for
//! it, delays included, and `stop` cancels it with the other request work.
//!
//! The writes are made one at a time, each through the same [`LocalWriter`]
//! path as `write_local`: priorities, command-source tracking, audit, COV and
//! the post-write event pass all apply as for any other local write. No
//! database guard is held across a write's notifications or a delay. The
//! object's generation guards every report back, so a run whose object was
//! replaced or reconfigured stops.

use super::local_writes::{LocalWrite, LocalWriter};
use super::request_tasks::RequestTaskSpawner;
use super::*;
use crate::command_lists::{RunHost, Unfinished};
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
    /// ends that run as failed rather than leaving its object busy.
    pub(super) fn start(&self, runs: Vec<CommandRun>) {
        use futures_util::FutureExt;
        for run in runs {
            let runner = self.clone();
            self.tasks.spawn(async move {
                let (source, generation) = (run.source, run.generation);
                let execution =
                    std::panic::AssertUnwindSafe(crate::command_lists::execute(&runner, run));
                if execution.catch_unwind().await.is_err() {
                    warn!(source = %source, "run panicked; ending it as failed");
                    crate::command_lists::complete(&runner, source, generation, false).await;
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
}

impl<T: TransportPort + 'static> RunHost for CommandRunner<T> {
    fn database(&self) -> &Arc<RwLock<ObjectDatabase>> {
        &self.db
    }

    /// Write one value through the local write path, with `run`'s object as
    /// the initiating object.
    async fn write(&self, run: &CommandRun, command: &BACnetActionCommand) -> Result<(), Error> {
        // The value reaches the target as a WriteProperty carrying the same
        // octets would, so constructed values take the shape the object
        // expects.
        let mut encoded = BytesMut::new();
        encode_property_value(&mut encoded, &command.property_value)?;
        let value = handlers::decode_write_property_value(
            command.property_identifier,
            command.property_array_index,
            &encoded,
        )?;
        let runs = self
            .writer()
            .write(
                &command.object_identifier,
                LocalWrite::Property {
                    property: command.property_identifier,
                    array_index: command.property_array_index,
                    priority: command.priority,
                },
                value,
                Some(crate::LocalCommandSource::Object(run.source)),
            )
            .await?;
        // A write that starts another Command's or Channel's run starts that
        // run too, unless it would close a loop.
        crate::command_lists::admit(self, run, runs, |runs| self.start(runs)).await
    }

    /// Timestamped references capture the change under its guard (#856).
    async fn committed(&self, db: &ObjectDatabase, source: ObjectIdentifier) {
        let capture = self.cov_table.read().await.timed_capture(source);
        capture.run(db);
    }

    /// Property subscribers hear of In_Process, All_Writes_Successful and
    /// Write_Status.
    async fn report(&self, source: ObjectIdentifier) {
        BACnetServer::<T>::fire_cov_notifications(&self.writer().cov_context(), &source).await;
    }

    /// The server cancels its runs only from `stop()`, which leaves them where
    /// they stood; a panic is ended in [`Self::start`].
    fn abandoned(&self, _left: Unfinished) {}
}
