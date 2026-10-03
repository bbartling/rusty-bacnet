//! Making the writes a Command or Channel object's Present_Value write
//! queues: a Command's action list (Clause 12.10) or a Channel's value for
//! each of its members (Clause 12.53, in `channel`).
//!
//! A Present_Value write that selects a list with commands sets In_Process,
//! and one that a Channel distributes sets Write_Status IN_PROGRESS; either
//! leaves a [`CommandRun`] on the object (#1150, #1151). Whatever commits that
//! write takes the run under the same guard and owns it from then on: it has
//! to finish the run, or the object stays busy and every later Present_Value
//! write is refused BUSY (#1178). Each owner finishes it in the way it can:
//!
//! - the bundled server runs it as a task beside the request that wrote it
//!   (`server::command_runs`);
//! - [`tick_schedules`](crate::schedule::tick_schedules) runs the runs its
//!   writes start before it returns ([`run_unattached`]);
//! - the synchronous WriteProperty and WritePropertyMultiple handlers have no
//!   task to wait out a delay in, so they end the run at once as unsuccessful
//!   ([`end_unmade`]).
//!
//! A server that stops ends what is left once its own work has stopped: runs
//! let go of while the database was busy, then any run nothing owns
//! ([`end_unowned`], #1252).
//!
//! [`execute`] is the sequence every runner shares. A Command's commands go
//! in list order, each through the owner's write path (a command naming
//! another device through [`RunHost::write_remote`]), each outcome recorded
//! under a generation check, the post delay after each attempt, a stop at a
//! failure that quits, then the end of the run. A Channel's members go in
//! delay order through the same write path. A run a write starts is admitted
//! through `chain`, which stops runs that feed back into themselves.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bacnet_objects::command::{CommandRun, RunPlan};
use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::traits::BACnetObject;
use bacnet_types::constructed::BACnetActionCommand;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::server::RemoteWriteError;

mod chain;
mod channel;
mod unattached;

pub(crate) use chain::admit;
pub(crate) use unattached::run_unattached;

/// What a runner needs from the component that owns its runs.
pub(crate) trait RunHost: Sync {
    /// The database holding the Command and Channel objects and their
    /// targets.
    fn database(&self) -> &Arc<RwLock<ObjectDatabase>>;

    /// Make one write on behalf of `run`'s object, as a WriteProperty
    /// carrying `command`'s value would, and start any run that write queued
    /// ([`admit`]). A Channel member's write is made as a command too.
    fn write(
        &self,
        run: &CommandRun,
        command: &BACnetActionCommand,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Make one write in `device`, another device, as a confirmed
    /// WriteProperty carrying `command`'s value. No database guard is held
    /// while it is outstanding.
    fn write_remote(
        &self,
        device: ObjectIdentifier,
        command: &BACnetActionCommand,
    ) -> impl Future<Output = Result<(), RemoteWriteError>> + Send;

    /// The object's run state changed under `db`, the guard that changed it.
    fn committed(
        &self,
        db: &ObjectDatabase,
        source: ObjectIdentifier,
    ) -> impl Future<Output = ()> + Send;

    /// Report that change once the guard is released.
    fn report(&self, source: ObjectIdentifier) -> impl Future<Output = ()> + Send;

    /// A run's future was dropped before the run ended. Called from `Drop`,
    /// so it can't wait for the database.
    fn abandoned(&self, left: Unfinished);
}

/// Where a run stood when its future let go of it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Unfinished {
    source: ObjectIdentifier,
    generation: u64,
    /// The first command, or member, not yet written.
    next: usize,
    len: usize,
    /// Whether every write made so far succeeded.
    all_succeeded: bool,
}

impl Unfinished {
    /// `run` before any of its writes is made.
    pub(crate) fn start(run: &CommandRun) -> Self {
        Self {
            source: run.source,
            generation: run.generation,
            next: 0,
            len: match &run.plan {
                RunPlan::Actions(commands) => commands.len(),
                RunPlan::Channel(distribution) => distribution.members.len(),
            },
            all_succeeded: true,
        }
    }

    /// The object the run belongs to.
    pub(crate) fn source(&self) -> ObjectIdentifier {
        self.source
    }

    /// Whether this is `source`'s run of `generation`.
    pub(crate) fn is(&self, source: ObjectIdentifier, generation: u64) -> bool {
        self.source == source && self.generation == generation
    }

    /// End the run where it stood, as successful only if every write was
    /// made and succeeded. A Command's commands never made read unsuccessful
    /// and In_Process returns to FALSE; a Channel's Write_Status becomes
    /// SUCCESSFUL or FAILED. Nothing changes once the object has moved on to
    /// another generation. Returns whether the run ended here.
    pub(crate) fn end(self, db: &mut ObjectDatabase) -> bool {
        db.get_mut(&self.source).is_some_and(|object| {
            for index in self.next..self.len {
                object.record_command_write_internal(self.generation, index, false);
            }
            object.complete_command_run_internal(
                self.generation,
                self.all_succeeded && self.next >= self.len,
            )
        })
    }
}

/// End `left` once the database is free, for a run let go of where nothing
/// else will end it.
pub(crate) fn end_when_free(db: &Arc<RwLock<ObjectDatabase>>, left: Unfinished) {
    when_free(db, move |db| {
        left.end(db);
    });
}

/// End `stranded`, runs let go of while the database was busy, where each
/// stood, then every run nothing owns ([`end_ownerless`]), for a server whose
/// own work has stopped. Whoever holds the database isn't waited for: the
/// runs then end as soon as it lets go.
pub(crate) fn end_unowned(db: &Arc<RwLock<ObjectDatabase>>, stranded: Vec<Unfinished>) {
    when_free(db, move |db| {
        for left in stranded {
            left.end(db);
        }
        end_ownerless(db);
    });
}

/// Run `end` under the database's write guard: at once if no guard is held,
/// otherwise from a task once the database is free.
///
/// The task is detached on purpose: its caller is a `Drop` or a `stop()` that
/// mustn't wait on a database an application holds, and nothing else would
/// end these runs. A runtime that shuts down before the task runs drops it;
/// that is logged, and the objects stay busy.
fn when_free(
    db: &Arc<RwLock<ObjectDatabase>>,
    end: impl FnOnce(&mut ObjectDatabase) + Send + 'static,
) {
    if let Ok(mut db) = db.try_write() {
        end(&mut db);
        return;
    }
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            let db = Arc::clone(db);
            runtime.spawn(async move {
                let mut waiting = Waiting(true);
                end(&mut *db.write().await);
                waiting.0 = false;
            });
        }
        Err(_) => warn!("runs let go of outside a runtime; their objects stay busy"),
    }
}

/// Logs a [`when_free`] task dropped before it could end its runs.
struct Waiting(bool);

impl Drop for Waiting {
    fn drop(&mut self) {
        if self.0 {
            warn!("runtime dropped the task ending runs let go of; their objects stay busy");
        }
    }
}

/// End every run on `db` that nothing owns any more, once nothing can own
/// one (#1252). A run in progress, or one queued on its object and never
/// taken, ends unsuccessful: a Command with each command marked
/// unsuccessful, a Channel with Write_Status FAILED. Runs whose progress is
/// known are ended first through [`Unfinished::end`], so this only meets
/// runs that made no write.
///
/// The sweep can't tell a server's runs from others on the same database: a
/// run an application's own `tick_schedules` is driving ends here too, and
/// that run then finds its generation stale and stops.
fn end_ownerless(db: &mut ObjectDatabase) {
    db.for_each_object_mut(|oid, object| {
        if end_ownerless_object(object) {
            debug!(source = %oid, "Ending a run nothing owns any more");
        }
    });
}

fn end_ownerless_object(object: &mut dyn BACnetObject) -> bool {
    // A run still queued on the object belongs to the generation in progress,
    // so ending that generation covers it.
    drop(object.take_command_run_internal());
    let Some(generation) = object.command_generation_internal() else {
        return false;
    };
    let mut index = 0;
    while object.record_command_write_internal(generation, index, false) {
        index += 1;
    }
    object.complete_command_run_internal(generation, false)
}

/// Take the runs that Present_Value writes queued on Command and Channel
/// objects among `oids`, under the guard that committed those writes. The
/// caller owns them.
pub(crate) fn take_runs(db: &mut ObjectDatabase, oids: &[ObjectIdentifier]) -> Vec<CommandRun> {
    oids.iter()
        .filter_map(|oid| {
            db.get_mut(oid)
                .and_then(|object| object.take_command_run_internal())
        })
        .collect()
}

/// End the runs that Present_Value writes queued on Command and Channel
/// objects among `oids` without making any of their writes, for an owner
/// that can't run them. Each ends at once as unsuccessful, so none is left
/// busy.
pub(crate) fn end_unmade(db: &mut ObjectDatabase, oids: &[ObjectIdentifier]) {
    for run in take_runs(db, oids) {
        debug!(
            source = %run.source,
            "Ending a run without its writes: this path can't make them"
        );
        Unfinished::start(&run).end(db);
    }
}

/// Make `run`'s writes, then end it.
///
/// The returned future owns the run from this call: dropping it before the
/// run ends, unpolled included, hands where the run stood to
/// [`RunHost::abandoned`].
pub(crate) fn execute<H: RunHost>(
    host: &H,
    run: CommandRun,
) -> impl Future<Output = ()> + Send + use<'_, H> {
    let mut owner = Owner {
        host,
        left: Some(Unfinished::start(&run)),
    };
    async move {
        let ended = match &run.plan {
            RunPlan::Actions(commands) => run_actions(host, &run, commands, &mut owner).await,
            RunPlan::Channel(distribution) => {
                channel::distribute(host, &run, distribution, &mut owner).await
            }
        };
        // `None`: the object changed under the run, and whatever replaced it
        // owns its run state now.
        if let Some(all_succeeded) = ended {
            complete(host, run.source, run.generation, all_succeeded).await;
        }
        owner.release();
    }
}

/// Make a Command's commands in order: whether all succeeded, or `None` once
/// the run is stale.
async fn run_actions<H: RunHost>(
    host: &H,
    run: &CommandRun,
    commands: &[BACnetActionCommand],
    owner: &mut Owner<'_, H>,
) -> Option<bool> {
    let mut all_succeeded = true;
    for (index, command) in commands.iter().enumerate() {
        let success = make(host, run, index, command).await?;
        all_succeeded &= success;
        owner.progress(index + 1, all_succeeded);
        // Clause 12.10.8: the delay follows every attempt, failed or not,
        // and comes before the next write or the end of the run.
        if let Some(delay) = command.post_delay {
            tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
        }
        if !success && command.quit_on_failure {
            break;
        }
    }
    Some(all_succeeded)
}

/// Holds where a run stands until it ends.
struct Owner<'h, H: RunHost> {
    host: &'h H,
    left: Option<Unfinished>,
}

impl<H: RunHost> Owner<'_, H> {
    /// `next` writes have been made, all successful if `all_succeeded`.
    fn progress(&mut self, next: usize, all_succeeded: bool) {
        if let Some(left) = &mut self.left {
            left.next = next;
            left.all_succeeded = all_succeeded;
        }
    }

    /// The run ended, or went stale: nothing is left to hand back.
    fn release(&mut self) {
        self.left = None;
    }
}

impl<H: RunHost> Drop for Owner<'_, H> {
    fn drop(&mut self) {
        if let Some(left) = self.left.take() {
            self.host.abandoned(left);
        }
    }
}

/// Make command `index` and record its outcome. `None` once the run is
/// stale.
async fn make<H: RunHost>(
    host: &H,
    run: &CommandRun,
    index: usize,
    command: &BACnetActionCommand,
) -> Option<bool> {
    let remote = {
        let db = host.database().read().await;
        if db
            .get(&run.source)
            .and_then(|object| object.command_generation_internal())
            != Some(run.generation)
        {
            return None;
        }
        // Naming this Device is the same as naming none. Clause 12.10.8
        // leaves writes to other devices optional; the server makes them over
        // the network, a runner without one fails them.
        if db.local_device().is_local(command.device_identifier) {
            None
        } else {
            command.device_identifier
        }
    };
    let success = match remote {
        None => match host.write(run, command).await {
            Ok(()) => true,
            Err(error) => {
                debug!(
                    command = %run.source,
                    target = %command.object_identifier,
                    property = ?command.property_identifier,
                    %error,
                    "Command write failed"
                );
                false
            }
        },
        Some(device) => match host.write_remote(device, command).await {
            Ok(()) => true,
            Err(error) => {
                debug!(
                    command = %run.source,
                    %device,
                    target = %command.object_identifier,
                    property = ?command.property_identifier,
                    %error,
                    "Command write to another device failed"
                );
                false
            }
        },
    };
    let recorded = {
        let mut db = host.database().write().await;
        let recorded = db.get_mut(&run.source).is_some_and(|object| {
            object.record_command_write_internal(run.generation, index, success)
        });
        if recorded {
            host.committed(&db, run.source).await;
        }
        recorded
    };
    if !recorded {
        return None;
    }
    host.report(run.source).await;
    Some(success)
}

/// End a run: a Command's In_Process back to FALSE and All_Writes_Successful
/// set, or a Channel's Write_Status set, reported through the host. Returns
/// whether the run ended here, rather than having ended or gone stale before.
pub(crate) async fn complete<H: RunHost>(
    host: &H,
    source: ObjectIdentifier,
    generation: u64,
    all_succeeded: bool,
) -> bool {
    let completed = {
        let mut db = host.database().write().await;
        let completed = db
            .get_mut(&source)
            .is_some_and(|object| object.complete_command_run_internal(generation, all_succeeded));
        if completed {
            host.committed(&db, source).await;
        }
        completed
    };
    if completed {
        host.report(source).await;
    }
    completed
}
