//! Audit Log commits off the database lock (#1270).
//!
//! Every commit runs on the log's writer thread ([`crate::durable`]). The
//! server stages an inbound notification batch, and a Log_Enable write it
//! receives: the log builds the next snapshot and queues its commit, goes on
//! serving the committed state, and takes the new snapshot only once the
//! commit is durable. The server awaits the commit after dropping the
//! database guard, so readers carry on meanwhile, and a confirmed batch is
//! still acknowledged only after its records and receipt are stored. A
//! commit that fails leaves the log as it was, and the request is refused.
//!
//! One commit is staged at a time; a request that finds one staged waits for
//! it without the guard. Code that changes the log in place (an
//! application's `add_record`, or a write nobody staged) first settles what
//! is staged: a batch whose commit ran is applied if it succeeded, its
//! outcome kept for the batch's request, and a staged write is dropped, its
//! request then committing in place.

use std::sync::Arc;
use std::time::Instant;

use super::*;
use crate::durable::{
    DurableWrites, Event, SaveTicket, SaveWait, SaveWriter, StageStep, STAGED_WRITE_LIFETIME,
};

/// Outcomes of batches settled before their requests came back for them.
const MAX_SETTLED: usize = 16;

/// What staging an Audit notification batch gave the caller.
#[derive(Debug)]
pub enum AuditBatchStage {
    /// No staged commit was needed: the batch's outcome, and whether its
    /// retained records changed. A duplicate confirmed batch, an unconfirmed
    /// one that changed nothing, and any batch to a sink that stores at once
    /// end here.
    Done(ConfirmedAuditNotificationOutcome, bool),
    /// The commit is queued. Await [`StagedAuditBatch::saved`] without the
    /// database guard, then pass the batch to
    /// [`AuditLogNotificationSink::finish_notification_batch`].
    Staged(StagedAuditBatch),
    /// Another staged commit holds the log. Await the wait, then stage the
    /// batch again.
    Busy(SaveWait),
}

/// A notification batch whose commit is queued on the Audit Log's writer.
#[derive(Debug)]
pub struct StagedAuditBatch {
    token: u64,
    saved: SaveWait,
}

impl StagedAuditBatch {
    /// A future that resolves once the commit has run.
    pub fn saved(&self) -> SaveWait {
        self.saved.clone()
    }
}

pub(super) enum StagedKind {
    Batch {
        token: u64,
        outcome: ConfirmedAuditNotificationOutcome,
        changed: bool,
    },
    Write {
        log_enable: bool,
    },
}

/// The next snapshot, held aside while its commit runs.
pub(super) struct StagedCommit {
    snapshot: Arc<AuditLogSnapshot>,
    ticket: SaveTicket,
    kind: StagedKind,
    /// Set when the commit is taken or dropped, for a request that found the
    /// log busy.
    released: Arc<Event>,
    staged_at: Instant,
}

/// A batch settled before its request finished it.
pub(super) struct Settled {
    token: u64,
    result: Result<(ConfirmedAuditNotificationOutcome, bool), Error>,
}

fn operational_problem() -> Error {
    Error::Protocol {
        class: ErrorClass::DEVICE.to_raw() as u32,
        code: ErrorCode::OPERATIONAL_PROBLEM.to_raw() as u32,
    }
}

/// The writer that commits `oid`'s snapshots to `persistence`.
pub(super) fn writer(
    oid: ObjectIdentifier,
    persistence: Arc<dyn AuditLogPersistence>,
) -> SaveWriter<Arc<AuditLogSnapshot>> {
    SaveWriter::new(
        format!("bacnet-al-{}-save", oid.instance_number()),
        move |snapshot: &Arc<AuditLogSnapshot>| persistence.commit(snapshot),
        move |snapshot, result| {
            if let Err(error) = result {
                tracing::warn!(
                    audit_log = %oid,
                    generation = snapshot.generation,
                    %error,
                    "Failed to commit Audit Log snapshot"
                );
            }
        },
    )
}

impl AuditLogObject {
    /// Commit `snapshot` and take it, waiting for the commit in place.
    pub(super) fn commit_and_apply(&mut self, snapshot: AuditLogSnapshot) -> Result<(), Error> {
        validate_snapshot(&snapshot)?;
        let snapshot = Arc::new(snapshot);
        self.writer.submit(Arc::clone(&snapshot)).take_outcome()?;
        self.apply_snapshot(snapshot);
        Ok(())
    }

    fn apply_snapshot(&mut self, snapshot: Arc<AuditLogSnapshot>) {
        let snapshot = Arc::try_unwrap(snapshot).unwrap_or_else(|shared| (*shared).clone());
        self.generation = snapshot.generation;
        self.log_enable = snapshot.log_enable;
        self.total_record_count = snapshot.total_record_count;
        self.buffer = snapshot.records.into();
        self.completed_receipts = snapshot.completed_receipts;
    }

    /// Before the log builds on its state in place, let a staged commit
    /// land, waiting for it if it is still running.
    pub(super) fn settle_staged(&mut self) {
        let Some(commit) = self.staged.take() else {
            return;
        };
        commit.released.set();
        match commit.kind {
            StagedKind::Batch {
                token,
                outcome,
                changed,
            } => {
                let result = commit.ticket.take_outcome().map(|()| {
                    self.apply_snapshot(commit.snapshot);
                    (outcome, changed)
                });
                if self.settled.len() == MAX_SETTLED {
                    self.settled.pop_front();
                }
                self.settled.push_back(Settled { token, result });
            }
            StagedKind::Write { .. } => self.drop_staged_write(&commit.ticket),
        }
    }

    /// A staged write is dropped without being taken. Its commit may have
    /// left storage with a snapshot the log never served, at the generation
    /// after the current one; commit the served state at that generation so
    /// storage follows the log again. A commit made in place right after
    /// lands later and replaces it.
    fn drop_staged_write(&mut self, ticket: &SaveTicket) {
        if ticket.succeeded() == Some(false) {
            return;
        }
        let Some(generation) = self.generation.checked_add(1) else {
            return;
        };
        let mut served = self.current_snapshot();
        served.generation = generation;
        self.writer.submit_coalescing(Arc::new(served));
    }

    /// The wait for a staged commit that still holds the log: a batch's
    /// while its commit runs, a write's until its request takes or drops it
    /// (or [`STAGED_WRITE_LIFETIME`] after its commit ran). A batch whose
    /// commit ran is settled, and a forgotten write dropped.
    fn make_way(&mut self) -> Option<SaveWait> {
        let commit = self.staged.as_ref()?;
        let holds = match commit.kind {
            StagedKind::Batch { .. } => !commit.ticket.is_done(),
            StagedKind::Write { .. } => {
                !commit.ticket.is_done() || commit.staged_at.elapsed() < STAGED_WRITE_LIFETIME
            }
        };
        if holds {
            return Some(match commit.kind {
                StagedKind::Batch { .. } => commit.ticket.wait(),
                StagedKind::Write { .. } => SaveWait::new(Arc::clone(&commit.released)),
            });
        }
        self.settle_staged();
        None
    }

    fn queue_staged(&mut self, snapshot: AuditLogSnapshot, kind: StagedKind) -> SaveWait {
        let snapshot = Arc::new(snapshot);
        let ticket = self.writer.submit(Arc::clone(&snapshot));
        let saved = ticket.wait();
        self.staged = Some(StagedCommit {
            snapshot,
            ticket,
            kind,
            released: Arc::default(),
            staged_at: Instant::now(),
        });
        saved
    }

    /// Stage a notification batch: build the next snapshot as
    /// `store_confirmed_notifications_with_change` (with a receipt) or
    /// `store_notifications_with_change` (without) would, and queue its
    /// commit.
    pub(super) fn stage_notification_batch(
        &mut self,
        notifications: &[BACnetAuditNotification],
        apdu_timeout_ms: u32,
        receipt: Option<CompletedAuditReceipt>,
    ) -> Result<AuditBatchStage, Error> {
        if let Some(wait) = self.make_way() {
            return Ok(AuditBatchStage::Busy(wait));
        }
        if !self.log_enable {
            return Err(Error::Protocol {
                class: ErrorClass::SERVICES.to_raw() as u32,
                code: ErrorCode::SERVICE_REQUEST_DENIED.to_raw() as u32,
            });
        }
        if notifications.is_empty() {
            return Err(Error::OutOfRange(
                "Audit notification batch must not be empty".into(),
            ));
        }
        if let Some(receipt) = &receipt {
            if receipt::contains(
                &self.completed_receipts,
                receipt.key(),
                receipt.completed_at_unix_millis(),
            )? {
                return Ok(AuditBatchStage::Done(
                    ConfirmedAuditNotificationOutcome::Duplicate,
                    false,
                ));
            }
        }
        let mut prospective = self.snapshot_for_next_generation()?;
        let changed =
            self.apply_notification_batch(&mut prospective, notifications, apdu_timeout_ms)?;
        let confirmed = receipt.is_some();
        let outcome = match receipt {
            Some(receipt) => receipt::insert(&mut prospective.completed_receipts, receipt)?,
            None => ConfirmedAuditNotificationOutcome::Stored,
        };
        // As in place: a duplicate commits nothing, and neither does an
        // unconfirmed batch that changes no record.
        if outcome == ConfirmedAuditNotificationOutcome::Duplicate || (!confirmed && !changed) {
            return Ok(AuditBatchStage::Done(outcome, false));
        }
        let changed = changed && self.buffer_size != 0;
        validate_snapshot(&prospective)?;
        self.next_token = self.next_token.wrapping_add(1);
        let token = self.next_token;
        let saved = self.queue_staged(
            prospective,
            StagedKind::Batch {
                token,
                outcome,
                changed,
            },
        );
        Ok(AuditBatchStage::Staged(StagedAuditBatch { token, saved }))
    }

    /// Take a staged batch once its commit has run: apply it if the commit
    /// succeeded, or return the commit's error and leave the log as it was.
    pub(super) fn finish_notification_batch(
        &mut self,
        staged: StagedAuditBatch,
    ) -> Result<(ConfirmedAuditNotificationOutcome, bool), Error> {
        let ours = self.staged.as_ref().is_some_and(|commit| {
            matches!(commit.kind, StagedKind::Batch { token, .. } if token == staged.token)
        });
        if ours {
            self.settle_staged();
        }
        let index = self
            .settled
            .iter()
            .position(|settled| settled.token == staged.token)
            .ok_or_else(operational_problem)?;
        self.settled
            .remove(index)
            .expect("index found above")
            .result
    }

    /// Take a staged Log_Enable write of `log_enable`, if one is staged on
    /// the current state.
    pub(super) fn claim_log_enable(&mut self, log_enable: bool) -> Option<Result<(), Error>> {
        let commit = self.staged.as_ref()?;
        let matches = matches!(commit.kind, StagedKind::Write { log_enable: staged } if staged == log_enable)
            && self.generation.checked_add(1) == Some(commit.snapshot.generation);
        if !matches {
            return None;
        }
        let commit = self.staged.take().expect("matched above");
        commit.released.set();
        Some(
            commit
                .ticket
                .take_outcome()
                .map(|()| self.apply_snapshot(commit.snapshot)),
        )
    }

    /// From the operation task: settle a batch whose commit has run, and drop
    /// a write its request forgot.
    pub(super) fn settle_finished(&mut self) -> bool {
        let Some(commit) = &self.staged else {
            return false;
        };
        let finished = commit.ticket.is_done()
            && match commit.kind {
                StagedKind::Batch { .. } => true,
                StagedKind::Write { .. } => commit.staged_at.elapsed() >= STAGED_WRITE_LIFETIME,
            };
        if finished {
            self.settle_staged();
        }
        finished
    }

    /// Block until every queued commit has run.
    #[cfg(test)]
    pub(super) fn wait_for_commits(&self) {
        self.writer.wait_idle();
    }
}

impl DurableWrites for AuditLogObject {
    fn stage_write(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: &PropertyValue,
    ) -> StageStep {
        let (PropertyIdentifier::LOG_ENABLE, None, PropertyValue::Boolean(log_enable)) =
            (property, array_index, value)
        else {
            return StageStep::Skip;
        };
        if let Some(wait) = self.make_way() {
            return StageStep::Busy(wait);
        }
        if *log_enable == self.log_enable {
            return StageStep::Skip;
        }
        let Ok(timestamp) = self.valid_timestamp() else {
            return StageStep::Skip;
        };
        let Ok(mut prospective) = self.snapshot_for_next_generation() else {
            return StageStep::Skip;
        };
        prospective.log_enable = *log_enable;
        append_record(&mut prospective, log_enable_record(timestamp, *log_enable));
        if validate_snapshot(&prospective).is_err() {
            return StageStep::Skip;
        }
        StageStep::Staged(self.queue_staged(
            prospective,
            StagedKind::Write {
                log_enable: *log_enable,
            },
        ))
    }

    fn release_staged_write(&mut self) {
        if matches!(
            self.staged.as_ref().map(|commit| &commit.kind),
            Some(StagedKind::Write { .. })
        ) {
            self.settle_staged();
        }
    }
}
