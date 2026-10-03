//! Running Command lists and Channel distributions without a server, for
//! [`tick_schedules`](crate::schedule::tick_schedules) (#1178, #1151).
//!
//! Each write is made as the bare WriteProperty handler would make a request
//! carrying it, with the Command or Channel as the initiating object. There
//! is no COV table, notification path or task set here, so nothing is
//! reported and the runs go on inside the caller's future: a run that writes
//! another Command's or Channel's Present_Value starts that run beside it,
//! and the call returns once every run has ended.

use std::sync::Arc;

use bacnet_encoding::primitives::encode_property_value;
use bacnet_objects::command::CommandRun;
use bacnet_objects::database::ObjectDatabase;
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::constructed::BACnetActionCommand;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::sync::{mpsc, RwLock};
use tracing::warn;

use super::{execute, RunHost, Unfinished};

/// Run `runs`, and any runs their writes start, to their ends.
///
/// Dropping the returned future first ends each unfinished run as
/// unsuccessful, so none is left in process.
pub(crate) async fn run_unattached(db: &Arc<RwLock<ObjectDatabase>>, runs: Vec<CommandRun>) {
    if runs.is_empty() {
        return;
    }
    let (started, mut queued) = mpsc::unbounded_channel();
    let host = Unattached { db, started };
    let mut running: FuturesUnordered<_> =
        runs.into_iter().map(|run| execute(&host, run)).collect();
    loop {
        // A run is only started from inside another's write, so once none is
        // left running and none is queued, nothing more can start.
        while let Ok(run) = queued.try_recv() {
            running.push(execute(&host, run));
        }
        if running.is_empty() {
            break;
        }
        tokio::select! {
            Some(run) = queued.recv() => running.push(execute(&host, run)),
            Some(()) = running.next() => {}
            else => break,
        }
    }
}

struct Unattached<'a> {
    db: &'a Arc<RwLock<ObjectDatabase>>,
    started: mpsc::UnboundedSender<CommandRun>,
}

impl RunHost for Unattached<'_> {
    fn database(&self) -> &Arc<RwLock<ObjectDatabase>> {
        self.db
    }

    async fn write(&self, run: &CommandRun, command: &BACnetActionCommand) -> Result<(), Error> {
        let request = request(command)?;
        let runs = {
            let mut db = self.db.write().await;
            let origin = crate::command_source::resolve_local(
                &db,
                crate::LocalCommandSource::Object(run.source),
            )
            .ok();
            let target = crate::handlers::handle_write_property_observed(
                &mut db,
                &request,
                None,
                None,
                origin.as_ref(),
            )?;
            super::take_runs(&mut db, &[target])
        };
        super::admit(self, run, runs, |runs| {
            for run in runs {
                // The receiver lives as long as this host.
                let _ = self.started.send(run);
            }
        })
        .await
    }

    async fn committed(&self, _db: &ObjectDatabase, _source: ObjectIdentifier) {}

    async fn report(&self, _source: ObjectIdentifier) {}

    fn abandoned(&self, left: Unfinished) {
        if let Ok(mut db) = self.db.try_write() {
            left.end(&mut db);
            return;
        }
        // Someone else holds the database; end the run once it's free.
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let db = Arc::clone(self.db);
                runtime.spawn(async move { left.end(&mut *db.write().await) });
            }
            Err(_) => warn!(
                source = %left.source(),
                "run dropped outside a runtime; its object stays busy"
            ),
        }
    }
}

/// The WriteProperty request a command amounts to.
fn request(command: &BACnetActionCommand) -> Result<Vec<u8>, Error> {
    let mut value = BytesMut::new();
    encode_property_value(&mut value, &command.property_value)?;
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: command.object_identifier,
        property_identifier: command.property_identifier,
        property_array_index: command.property_array_index,
        property_value: value.to_vec(),
        priority: command.priority,
    }
    .encode(&mut request)?;
    Ok(request.to_vec())
}
