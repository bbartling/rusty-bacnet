//! Running Command lists and Channel distributions without a server, for
//! [`tick_schedules`](crate::schedule::tick_schedules) (#1178, #1151).
//!
//! Each write is made as the bare WriteProperty handler would make a request
//! carrying it, with the Command or Channel as the initiating object. There
//! is no COV table, notification path or task set here, so nothing is
//! reported and the runs go on inside the caller's future: a run that writes
//! another Command's or Channel's Present_Value starts that run beside it,
//! and the call returns once every run has ended.

use std::future::Future;
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
/// Dropping the returned future first, unpolled included, ends each
/// unfinished run as unsuccessful, so none is left busy: a run being made
/// through its [`execute`] owner, and one queued but not yet started through
/// the queue's own guard.
pub(crate) fn run_unattached(
    db: &Arc<RwLock<ObjectDatabase>>,
    runs: Vec<CommandRun>,
) -> impl Future<Output = ()> + Send + '_ {
    let (started, queued) = mpsc::unbounded_channel();
    for run in runs {
        // The receiver is in hand.
        let _ = started.send(run);
    }
    let mut queue = Queue { db, queued };
    async move {
        let host = Unattached { db, started };
        let mut running = FuturesUnordered::new();
        loop {
            // A run is only started from inside another's write, so once none
            // is left running and none is queued, nothing more can start.
            while let Ok(run) = queue.queued.try_recv() {
                running.push(execute(&host, run));
            }
            if running.is_empty() {
                break;
            }
            // Queued runs first, so each gets its owner as soon as it can.
            tokio::select! {
                biased;
                Some(run) = queue.queued.recv() => running.push(execute(&host, run)),
                Some(()) = running.next() => {}
                else => break,
            }
        }
    }
}

/// Runs queued for [`run_unattached`] and not yet started. Dropping it ends
/// each as unsuccessful.
struct Queue<'a> {
    db: &'a Arc<RwLock<ObjectDatabase>>,
    queued: mpsc::UnboundedReceiver<CommandRun>,
}

impl Drop for Queue<'_> {
    fn drop(&mut self) {
        self.queued.close();
        while let Ok(run) = self.queued.try_recv() {
            abandon(self.db, Unfinished::start(&run));
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
        abandon(self.db, left);
    }
}

/// End a run let go of before it ended: at once if the database is free,
/// otherwise once it is.
fn abandon(db: &Arc<RwLock<ObjectDatabase>>, left: Unfinished) {
    if let Ok(mut db) = db.try_write() {
        left.end(&mut db);
        return;
    }
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            let db = Arc::clone(db);
            runtime.spawn(async move { left.end(&mut *db.write().await) });
        }
        Err(_) => warn!(
            source = %left.source(),
            "run dropped outside a runtime; its object stays busy"
        ),
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

#[cfg(test)]
#[path = "unattached_tests.rs"]
mod tests;
