use super::*;
use crate::command_lists::TakenRuns;
use crate::life_safety_cov::LifeSafetyCovChange;
use crate::mutation::{
    MutationAuthorizationContext, MutationDecision, MutationDecisions, MutationPolicy,
    MutationTarget, MutationTrust,
};
use bacnet_objects::staging::StagingWritePlan;
use bacnet_services::cov::{SubscribeCOVPropertyRequest, SubscribeCOVRequest};
use bacnet_services::cov_multiple::SubscribeCOVPropertyMultipleRequest;
use bacnet_services::file::AtomicWriteFileRequest;
use bacnet_services::list_manipulation::ListElementRequest;
use bacnet_services::object_mgmt::{CreateObjectRequest, DeleteObjectRequest};
use bacnet_services::write_property::WritePropertyRequest;

pub(super) enum InitialCovNotification {
    Single(Box<CovSubscriptionSnapshot>),
    Multiple(Vec<CovSubscriptionSnapshot>),
}

/// Post-write work a mutating service collects while it runs, consumed after
/// the response is built: written objects for event evaluation, COV changes,
/// staged writes to execute and Command runs to start.
#[derive(Default)]
pub(super) struct MutationEffects {
    pub(super) written_oids: Vec<ObjectIdentifier>,
    pub(super) coarse_cov_oids: Vec<ObjectIdentifier>,
    pub(super) life_safety_cov_changes: Vec<LifeSafetyCovChange>,
    pub(super) staging_plans: Vec<StagingWritePlan>,
    /// Command lists and Channel distributions a Present_Value write
    /// started (#1150), ended if dropped before they start (#1324).
    pub(super) command_runs: TakenRuns,
    /// Timestamped references to evaluate again after the post-write fanout,
    /// which may not have selected them (#856).
    pub(super) timed_revisits: Vec<crate::cov::CovSubscriptionKey>,
}

/// Borrowed dispatch inputs; constructed only after the DCC precheck.
/// `provenance` is the reassembled ingress snapshot (fail-closed at
/// reassembly on cross-segment mismatch), threaded unchanged into every
/// authorization context built from this request.
pub(super) struct Request<'a> {
    pub config: &'a ServerConfig,
    pub decisions: &'a MutationDecisions,
    pub source_mac: &'a [u8],
    pub source_network: Option<&'a NpduAddress>,
    pub provenance: bacnet_transport::port::TransportProvenance,
    pub req: &'a ConfirmedRequestPdu,
    pub command_origin: Option<&'a bacnet_objects::command_source::CommandOrigin>,
}

impl Request<'_> {
    fn authorize(
        &self,
        decode: impl FnOnce() -> Result<MutationTarget, Error>,
    ) -> Result<(), Error> {
        if self.config.mutation_policy == MutationPolicy::Permissive
            && self.config.mutation_authorizer.is_none()
        {
            self.decisions
                .record(self.req.service_choice, MutationDecision::Allow);
            return Ok(());
        }
        let target = decode()?;
        if self.config.mutation_policy == MutationPolicy::DenyAll {
            self.decisions
                .record(self.req.service_choice, MutationDecision::PolicyDeny);
            return Err(audit_notification::request_denied());
        }
        let Some(authorizer) = &self.config.mutation_authorizer else {
            unreachable!("permissive absence handled above")
        };
        let context = MutationAuthorizationContext {
            source_mac: MacAddr::from_slice(self.source_mac),
            source_network: self.source_network.cloned(),
            provenance: self.provenance,
            trust: MutationTrust::from_provenance(self.provenance),
            invoke_id: self.req.invoke_id,
            service_choice: self.req.service_choice,
            target,
        };
        if audit_notification::fail_closed_authorize(|| authorizer(&context)) {
            self.decisions
                .record(self.req.service_choice, MutationDecision::Allow);
            Ok(())
        } else {
            self.decisions
                .record(self.req.service_choice, MutationDecision::Deny);
            Err(audit_notification::request_denied())
        }
    }

    fn error<T: TransportPort + 'static>(&self, error: &Error) -> Apdu {
        BACnetServer::<T>::error_apdu_from_error(self.req.invoke_id, self.req.service_choice, error)
    }

    fn simple_ack(&self) -> Apdu {
        Apdu::SimpleAck(SimpleAck {
            invoke_id: self.req.invoke_id,
            service_choice: self.req.service_choice,
        })
    }

    fn complex_ack(&self, ack_buf: BytesMut) -> Apdu {
        Apdu::ComplexAck(ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id: self.req.invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: self.req.service_choice,
            service_ack: ack_buf.freeze(),
        })
    }

    pub(super) async fn write_property<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        effects: &mut MutationEffects,
        audit: &mut audit_reporter::WriteAudit<'_, T>,
    ) -> Apdu {
        let MutationEffects {
            written_oids,
            coarse_cov_oids,
            life_safety_cov_changes,
            staging_plans,
            command_runs,
            ..
        } = effects;
        if let Err(error) = self.authorize(|| {
            WritePropertyRequest::decode(&self.req.service_request)
                .map(MutationTarget::WriteProperty)
        }) {
            return self.error::<T>(&error);
        }
        // A write the object saves first saves here, without the guard.
        let staged = durable_writes::stage(
            db,
            durable_writes::DurableTarget::write_property(&self.req.service_request),
        )
        .await;
        let database = db;
        let (result, exact_changes, plans, schedule_cov) = {
            let mut db = db.write().await;
            let snapshots = crate::life_safety_cov::LifeSafetyCovSnapshots::capture_write_property(
                &db,
                &self.req.service_request,
            );
            let source = audit.write_source();
            let result = handlers::handle_write_property_observed(
                &mut db,
                &self.req.service_request,
                Some(audit),
                Some(&source),
                self.command_origin,
            );
            staged.release(&mut db);
            // Post-write work follows a change. A NULL the property left as
            // it was (`handlers::relinquish`) is acknowledged with none.
            let written = match &result {
                Ok((oid, handlers::Applied::Written)) => Some(*oid),
                Ok((_, handlers::Applied::Unchanged)) | Err(_) => None,
            };
            let changes = written
                .map(|oid| snapshots.changes(&db, std::slice::from_ref(&oid)))
                .unwrap_or_default();
            let plans = written.map_or_else(Vec::new, |oid| {
                BACnetServer::<T>::take_staging_plans(&mut db, std::slice::from_ref(&oid))
            });
            if let Some(oid) = written {
                command_runs.extend(TakenRuns::take(
                    database,
                    &mut db,
                    std::slice::from_ref(&oid),
                ));
                let capture = {
                    let table = cov_table.read().await;
                    if crate::life_safety_cov::is_life_safety_object(oid) {
                        table.timed_capture_exact(&changes)
                    } else {
                        table.timed_capture(oid)
                    }
                };
                capture.run(&db);
            }
            let schedule_cov = match written {
                Some(oid) => {
                    crate::schedule::reevaluate_written(
                        database,
                        &mut db,
                        std::slice::from_ref(&oid),
                        cov_table,
                    )
                    .await
                }
                None => Default::default(),
            };
            (result.map(|_| written), changes, plans, schedule_cov)
        };
        staging_plans.extend(plans);
        let response = match result {
            Ok(Some(oid)) => {
                written_oids.push(oid);
                if crate::life_safety_cov::is_life_safety_object(oid) {
                    *life_safety_cov_changes = exact_changes;
                } else {
                    coarse_cov_oids.push(oid);
                }
                self.simple_ack()
            }
            Ok(None) => self.simple_ack(),
            Err(e) => self.error::<T>(&e),
        };
        // Targets a written Schedule commanded on re-evaluation.
        schedule_cov.merge_into(coarse_cov_oids, life_safety_cov_changes, command_runs);
        response
    }

    pub(super) async fn write_property_multiple<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        effects: &mut MutationEffects,
        audit: &mut audit_reporter::WriteAudit<'_, T>,
    ) -> Apdu {
        let MutationEffects {
            written_oids,
            coarse_cov_oids,
            life_safety_cov_changes,
            staging_plans,
            command_runs,
            timed_revisits,
        } = effects;
        // Attempts the objects save first save here, without the guard. That
        // needs each attempt allowed before the handler reaches it, which only
        // a permissive policy with no authorizer promises; otherwise those
        // attempts save in place.
        let targets = if self.config.mutation_policy == MutationPolicy::Permissive
            && self.config.mutation_authorizer.is_none()
        {
            durable_writes::DurableTarget::write_property_multiple(&self.req.service_request)
        } else {
            Vec::new()
        };
        let staged = durable_writes::stage(db, targets).await;
        let database = db;
        let (outcome, exact_changes, plans, schedule_cov) = {
            let mut db = db.write().await;
            // Lock order: database, then a short table read. Each attempt is
            // captured as it commits, under this guard (#856).
            let capture = cov_table.read().await.timed_capture_all();
            let mut snapshots = crate::life_safety_cov::LifeSafetyCovSnapshots::default();
            let authorize = |attempt: &bacnet_services::wpm::WritePropertyAttempt| {
                self.authorize(|| Ok(MutationTarget::WritePropertyMultiple(attempt.clone())))
            };
            let source = audit.write_source();
            let mut observer = crate::cov::TimedWriteCapture::new(capture, Some(audit));
            let outcome = handlers::handle_write_property_multiple_observed(
                &mut db,
                &self.req.service_request,
                &mut snapshots,
                Some(&authorize),
                Some(&mut observer),
                Some(&source),
                self.command_origin,
            );
            staged.release(&mut db);
            let committed_oids = match &outcome {
                handlers::WritePropertyMultipleOutcome::Success { committed_oids }
                | handlers::WritePropertyMultipleOutcome::Error { committed_oids, .. } => {
                    committed_oids.as_slice()
                }
                handlers::WritePropertyMultipleOutcome::Reject { .. } => &[],
            };
            let changes = snapshots.changes(&db, committed_oids);
            timed_revisits.extend_from_slice(observer.life_safety_queued());
            let plans = BACnetServer::<T>::take_staging_plans(&mut db, committed_oids);
            command_runs.extend(TakenRuns::take(database, &mut db, committed_oids));
            let schedule_cov =
                crate::schedule::reevaluate_written(database, &mut db, committed_oids, cov_table)
                    .await;
            (outcome, changes, plans, schedule_cov)
        };
        staging_plans.extend(plans);
        let response = match outcome {
            handlers::WritePropertyMultipleOutcome::Success { committed_oids } => {
                *written_oids = committed_oids;
                self.simple_ack()
            }
            handlers::WritePropertyMultipleOutcome::Error {
                error,
                first_failed_write_attempt,
                committed_oids,
            } => {
                *written_oids = committed_oids;
                let (error_class, error_code) = confirmed_response::error_fields(&error);
                Apdu::Error(
                    bacnet_services::wpm::WritePropertyMultipleError {
                        error_class,
                        error_code,
                        first_failed_write_attempt,
                    }
                    .to_error_pdu(self.req.invoke_id),
                )
            }
            handlers::WritePropertyMultipleOutcome::Reject { reason } => Apdu::Reject(RejectPdu {
                invoke_id: self.req.invoke_id,
                reject_reason: reason,
            }),
        };
        coarse_cov_oids.extend(
            written_oids
                .iter()
                .copied()
                .filter(|oid| !crate::life_safety_cov::is_life_safety_object(*oid)),
        );
        *life_safety_cov_changes = exact_changes;
        // Targets a written Schedule commanded on re-evaluation.
        schedule_cov.merge_into(coarse_cov_oids, life_safety_cov_changes, command_runs);
        response
    }

    pub(super) async fn subscribe_cov<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        initial_cov_notifications: &mut Vec<InitialCovNotification>,
    ) -> Apdu {
        if let Err(error) = self.authorize(|| {
            SubscribeCOVRequest::decode(&self.req.service_request).map(MutationTarget::SubscribeCov)
        }) {
            return self.error::<T>(&error);
        }
        let db = db.read().await;
        let mut table = cov_table.write().await;
        match handlers::handle_subscribe_cov_with_initial_endpoint(
            &mut table,
            &db,
            self.source_mac,
            self.source_network,
            &self.req.service_request,
        ) {
            Ok(subscriptions) => {
                initial_cov_notifications.extend(
                    subscriptions
                        .into_iter()
                        .map(Box::new)
                        .map(InitialCovNotification::Single),
                );
                self.simple_ack()
            }
            Err(e) => self.error::<T>(&e),
        }
    }

    pub(super) async fn subscribe_cov_property<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        initial_cov_notifications: &mut Vec<InitialCovNotification>,
    ) -> Apdu {
        if let Err(error) = self.authorize(|| {
            SubscribeCOVPropertyRequest::decode(&self.req.service_request)
                .map(MutationTarget::SubscribeCovProperty)
        }) {
            return self.error::<T>(&error);
        }
        let db = db.read().await;
        let mut table = cov_table.write().await;
        match handlers::handle_subscribe_cov_property_with_initial_endpoint(
            &mut table,
            &db,
            self.source_mac,
            self.source_network,
            &self.req.service_request,
        ) {
            Ok(subscriptions) => {
                initial_cov_notifications.extend(
                    subscriptions
                        .into_iter()
                        .map(Box::new)
                        .map(InitialCovNotification::Single),
                );
                self.simple_ack()
            }
            Err(e) => self.error::<T>(&e),
        }
    }

    pub(super) async fn create_object<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        mut ack_buf: BytesMut,
        audit: &mut super::super::audit_reporter::WriteAudit<'_, T>,
    ) -> Apdu {
        if let Err(error) = self.authorize(|| {
            CreateObjectRequest::decode(&self.req.service_request).map(MutationTarget::CreateObject)
        }) {
            return self.error::<T>(&error);
        }
        let result = {
            let mut db = db.write().await;
            let mut target = None;
            let result = handlers::handle_create_object_observed(
                &mut db,
                &self.req.service_request,
                &mut ack_buf,
                &mut target,
                self.command_origin,
            );
            // Initial application values are decoded inside the handler, possibly
            // after earlier values were applied. Rollback is already complete;
            // malformed values remain invalid requests, not auditable executions.
            let result = match result {
                Ok(()) => Ok(()),
                Err(handlers::CreateObjectRefusal::Malformed(error)) => {
                    return self.error::<T>(&error)
                }
                Err(handlers::CreateObjectRefusal::Failed(error)) => Err(error),
            };
            // Decode failures are not execution outcomes. No await separates the
            // completed mutation (including rollback) from audit admission.
            if let Ok(request) = CreateObjectRequest::decode(&self.req.service_request) {
                let kind = match request.object_specifier {
                    bacnet_services::object_mgmt::ObjectSpecifier::Type(kind) => kind,
                    bacnet_services::object_mgmt::ObjectSpecifier::Identifier(oid) => {
                        oid.object_type()
                    }
                };
                audit.before_lifecycle(
                    &db,
                    bacnet_types::enums::AuditOperation::CREATE,
                    target,
                    kind,
                    result.is_ok(),
                );
                audit.lifecycle_completed(&mut db, &result);
            }
            result
        };
        match result {
            Ok(()) => self.complex_ack(ack_buf),
            Err(e) => self.error::<T>(&e),
        }
    }

    pub(super) async fn delete_object<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        audit: &mut super::super::audit_reporter::WriteAudit<'_, T>,
    ) -> Apdu {
        if let Err(error) = self.authorize(|| {
            DeleteObjectRequest::decode(&self.req.service_request).map(MutationTarget::DeleteObject)
        }) {
            return self.error::<T>(&error);
        }
        let deleted_oid = DeleteObjectRequest::decode(&self.req.service_request)
            .ok()
            .map(|r| r.object_identifier);
        let (result, removed) = {
            let mut db = db.write().await;
            let removed_status = deleted_oid.and_then(|oid| {
                db.get(&oid)
                    .and_then(|object| object.audit_reporter_internal())
                    .map(|reporter| reporter.status_internal())
            });
            if let Some(oid) = deleted_oid {
                audit.before_lifecycle(
                    &db,
                    bacnet_types::enums::AuditOperation::DELETE,
                    Some(oid),
                    oid.object_type(),
                    true,
                );
            }
            let (result, removed) =
                match handlers::handle_delete_object(&mut db, &self.req.service_request) {
                    Ok(removed) => (Ok(()), Some(removed)),
                    Err(error) => (Err(error), None),
                };
            if result.is_ok() {
                if let Some(status) = removed_status {
                    status.set_configured(false);
                }
            }
            audit.lifecycle_completed(&mut db, &result);
            (result, removed)
        };
        // Dropping an object that saves its state waits for its queued saves,
        // so drop it with the guard released and off the async workers.
        if let Some(removed) = removed {
            tokio::task::spawn_blocking(move || drop(removed));
        }
        match result {
            Ok(()) => {
                // Clean up COV subscriptions for the deleted object
                if let Some(oid) = deleted_oid {
                    let mut table = cov_table.write().await;
                    table.remove_for_object(oid);
                }
                self.simple_ack()
            }
            Err(e) => self.error::<T>(&e),
        }
    }

    pub(super) async fn atomic_write_file<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        audit: &mut super::super::audit_reporter::WriteAudit<'_, T>,
    ) -> Apdu {
        if let Err(error) = self.authorize(|| {
            AtomicWriteFileRequest::decode(&self.req.service_request)
                .map(MutationTarget::AtomicWriteFile)
        }) {
            return self.error::<T>(&error);
        }
        let mut db = db.write().await;
        BACnetServer::<T>::atomic_write_file_response(
            &mut db,
            self.req.invoke_id,
            &self.req.service_request,
            self.config.atomic_write_file_budget,
            audit,
        )
    }

    /// AddListElement (`remove` false) or RemoveListElement. A Schedule whose
    /// references changed runs its pass at once under the same guard, as
    /// after a WriteProperty, so an added target gets the current value and a
    /// removed one is relinquished (#1121). The edited object joins the
    /// per-write event evaluation, so an Alarm_Values edit that puts the
    /// watched value in or out of alarm starts its transition at once rather
    /// than at the next periodic tick.
    pub(super) async fn list_element<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        effects: &mut MutationEffects,
        audit: &mut super::super::audit_reporter::WriteAudit<'_, T>,
        remove: bool,
    ) -> Apdu {
        if let Err(error) = self.authorize(|| {
            ListElementRequest::decode(&self.req.service_request).map(if remove {
                MutationTarget::RemoveListElement
            } else {
                MutationTarget::AddListElement
            })
        }) {
            return self.error::<T>(&error);
        }
        // A list the object saves first saves here, without the guard.
        let staged = durable_writes::stage(
            db,
            durable_writes::DurableTarget::list_element(&self.req.service_request, remove),
        )
        .await;
        let database = db;
        let (result, written, schedule_cov) = {
            let mut db = db.write().await;
            let (result, written) = match handlers::handle_list_element_observed(
                &mut db,
                &self.req.service_request,
                remove,
                |db, request, current| audit.before_list(db, request, current),
            ) {
                Ok(oid) => (Ok(()), Some(oid)),
                Err(error) => (Err(error), None),
            };
            staged.release(&mut db);
            audit.lifecycle_completed(&mut db, &result);
            let schedule_cov = match written {
                Some(oid) => {
                    crate::schedule::reevaluate_written(database, &mut db, &[oid], cov_table).await
                }
                None => Default::default(),
            };
            (result, written, schedule_cov)
        };
        // Targets a Schedule commanded on re-evaluation.
        schedule_cov.merge_into(
            &mut effects.coarse_cov_oids,
            &mut effects.life_safety_cov_changes,
            &mut effects.command_runs,
        );
        effects.written_oids.extend(written);
        match result {
            Ok(()) => self.simple_ack(),
            Err(e) => self.error::<T>(&e),
        }
    }

    pub(super) async fn subscribe_cov_property_multiple<T: TransportPort + 'static>(
        &self,
        db: &Arc<RwLock<ObjectDatabase>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        initial_cov_notifications: &mut Vec<InitialCovNotification>,
    ) -> Apdu {
        let decoded = SubscribeCOVPropertyMultipleRequest::decode(&self.req.service_request);
        match decoded {
            Err(e) => self.error::<T>(&e),
            Ok(request) => {
                if let Err(error) = self.authorize(|| {
                    Ok(MutationTarget::SubscribeCovPropertyMultiple(
                        request.clone(),
                    ))
                }) {
                    return self.error::<T>(&error);
                }
                let db = db.read().await;
                let mut table = cov_table.write().await;
                match handlers::handle_subscribe_cov_property_multiple_request_endpoint(
                    &mut table,
                    &db,
                    self.source_mac,
                    self.source_network,
                    Some(self.req.max_apdu_length),
                    request,
                ) {
                    Ok(subscriptions) => {
                        if !subscriptions.is_empty() {
                            initial_cov_notifications
                                .push(InitialCovNotification::Multiple(subscriptions));
                        }
                        self.simple_ack()
                    }
                    // The references kept before the failed one are reported
                    // as an accepted request's would be (Clause 13.16.2).
                    Err(refusal) => {
                        if !refusal.committed.is_empty() {
                            initial_cov_notifications
                                .push(InitialCovNotification::Multiple(refusal.committed));
                        }
                        self.error::<T>(&refusal.error)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "mutation_policy_tests.rs"]
mod policy_tests;
