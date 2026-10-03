use super::cov_notify_context::CovNotifyContext;
use super::*;
use crate::handlers::{WriteCommitObserver, WriteTarget};
use bacnet_objects::staging::StagingWritePlan;

#[cfg(test)]
#[path = "input_present_value_tests.rs"]
mod input_present_value_tests;

#[cfg(test)]
#[path = "staging_local_writes_tests.rs"]
mod staging_local_writes_tests;

/// What a local mutation is, and on whose behalf.
///
/// Inputs and noncommandable Values distinguish application updates from
/// network-equivalent writes, including their Out_Of_Service ownership checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalWrite {
    /// A trusted local program performing a network-equivalent property write.
    Property {
        property: PropertyIdentifier,
        array_index: Option<u32>,
        priority: Option<u8>,
    },
    /// The application supplying a supported object's logical `Present_Value`.
    ApplicationPresentValue,
    /// The application supplying a Loop's measured `Controlled_Variable_Value`.
    ApplicationControlledVariableValue,
    /// The application supplying one sample to an Averaging object.
    ApplicationAveragingSample,
    /// The application reporting an Averaging sample attempt that produced no
    /// value.
    ApplicationAveragingMiss,
    /// The application supplying a Life Safety object's `Tracking_Value`.
    ApplicationTrackingValue,
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Arm or rearm a Life Safety object from trusted local application logic.
    ///
    /// This uses the object-internal state channel under the database write
    /// lock. Network WriteProperty and WritePropertyMultiple remain unable to
    /// forge `Operation_Expected`. After the lock is released, an actual
    /// `Operation_Expected` readback change uses the exact Life Safety COV path;
    /// rearming to the current value emits no notification.
    pub async fn set_life_safety_operation_expected_local(
        &self,
        oid: &ObjectIdentifier,
        operation: LifeSafetyOperation,
    ) -> Result<(), Error> {
        self.active_network()?;
        let changes = {
            let mut db = self.db.write().await;
            let snapshots = crate::life_safety_cov::LifeSafetyCovSnapshots::capture_oid(&db, *oid);
            let object = db.get_mut(oid).ok_or_else(|| Error::Protocol {
                class: ErrorClass::OBJECT.to_raw() as u32,
                code: ErrorCode::UNKNOWN_OBJECT.to_raw() as u32,
            })?;
            object.set_life_safety_operation_expected_internal(operation)?;
            let changes = snapshots.changes(&db, std::slice::from_ref(oid));
            let capture = self.cov_table.read().await.timed_capture_exact(&changes);
            capture.run(&db);
            changes
        };
        for change in changes {
            Self::fire_life_safety_cov_notifications(
                &self.local_cov_context(),
                &change.object_identifier,
                &change.changed_properties,
            )
            .await;
        }
        Ok(())
    }

    /// Write a property on a local object and fire the same post-write COV
    /// and event notifications that a network [`WriteProperty`] does. When target
    /// Audit reporting is configured, the same observer records eligible local
    /// writes with local Device provenance and no invoke ID; Device recipient
    /// changes retain their sole old/new pair owner. Eligible actual AV/BV Audit
    /// policy changes reserve immediate delivery before assignment; unavailable
    /// resources return SERVICES/SERVICE_REQUEST_DENIED without a policy change.
    ///
    /// This is the server-owned local-mutation entry point: it performs the
    /// write under the database lock — routing `OBJECT_NAME` through the name
    /// uniqueness check and index refresh, exactly like the network handler —
    /// then releases the lock and runs the COV/event trigger path so a
    /// subscription observes a local mutation just as it would a network one.
    /// `source` explicitly selects the Device or an existing initiating object.
    /// Tracked commands require a concrete selected Device; the selected Device
    /// retains correction ownership regardless of the local initiator. Unrelated
    /// properties preserve their behavior without a usable command origin.
    /// Low-level object setters deliberately bypass this notification owner.
    ///
    /// [`WriteProperty`]: bacnet_services::write_property::WritePropertyRequest
    pub async fn write_local(
        &self,
        oid: &ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
        source: crate::LocalCommandSource,
    ) -> Result<(), Error> {
        self.write_local_as(
            oid,
            LocalWrite::Property {
                property,
                array_index,
                priority,
            },
            value,
            Some(source),
        )
        .await
    }

    /// Supply a supported object's logical `Present_Value` from Rust application code.
    ///
    /// Analog, Binary and Multi-state Inputs, noncommandable Values, Loop
    /// (the control algorithm's output) and Life Safety Point and Zone opt in.
    /// Binary Input values are logical INACTIVE/ACTIVE states after Polarity,
    /// not raw physical states. The update runs the existing post-write
    /// intrinsic-event and COV processing after the database lock is released;
    /// configured delays and distribution policy still control delivery, and a
    /// COV_Increment still filters Present_Value reports.
    ///
    /// Applications are denied while `Out_Of_Service` is TRUE to protect a
    /// client's simulation value. This is local policy for Inputs and required
    /// by the object clauses for the supported Values and Loop. NULL is an
    /// invalid application value. Other object families fail closed; use
    /// [`BACnetServer::write_local`] for network-equivalent writes and sourced
    /// commands on commandable objects. The Python binding exposes this as
    /// `BACnetServer.set_present_value_local`.
    ///
    /// A Life Safety Point or Zone takes an Enumerated BACnetLifeSafetyState,
    /// a standard value or one from 256 to 65535, in or out of service, since
    /// clients never write its Present_Value. The update leaves
    /// Tracking_Value, Silenced and Operation_Expected alone, so any latching
    /// until reset is the application's (see
    /// [`BACnetServer::set_tracking_value_local`]). A change notifies
    /// SubscribeCOV and Present_Value property subscribers through the Life
    /// Safety COV path. The built-in objects run no intrinsic reporting, so
    /// the post-write event pass raises nothing for them.
    ///
    /// [`BACnetObject::set_present_value_internal`]: bacnet_objects::traits::BACnetObject::set_present_value_internal
    pub async fn set_present_value_local(
        &self,
        oid: &ObjectIdentifier,
        value: PropertyValue,
    ) -> Result<(), Error> {
        self.write_local_as(oid, LocalWrite::ApplicationPresentValue, value, None)
            .await
    }

    /// Supply a Loop's measured `Controlled_Variable_Value` from the
    /// application that runs its control algorithm.
    ///
    /// The value is a finite REAL: another datatype fails with PROPERTY /
    /// INVALID_DATA_TYPE and NaN or an infinity with PROPERTY /
    /// VALUE_OUT_OF_RANGE. An unknown object fails with OBJECT /
    /// UNKNOWN_OBJECT and any object other than a Loop with OBJECT /
    /// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, the same errors as
    /// [`BACnetServer::set_present_value_local`]. Unlike Present_Value it is
    /// accepted while `Out_Of_Service` is TRUE, because Out_Of_Service
    /// decouples only the output and Reliability from the algorithm.
    ///
    /// The update runs the same post-write COV processing as
    /// `set_present_value_local` once the database lock is released. A
    /// SubscribeCOVProperty on `Controlled_Variable_Value` is notified of the
    /// change; a SubscribeCOV on the Loop is not, since the Loop's COV report
    /// carries this value without being triggered by it, so its next report
    /// carries the new value. The property stays read-only over the network.
    pub async fn set_controlled_variable_value_local(
        &self,
        oid: &ObjectIdentifier,
        value: PropertyValue,
    ) -> Result<(), Error> {
        self.write_local_as(
            oid,
            LocalWrite::ApplicationControlledVariableValue,
            value,
            None,
        )
        .await
    }

    /// Record one sample for an Averaging object, taken by the application.
    ///
    /// The server samples an object that holds an `Object_Property_Reference`
    /// itself, every Window_Interval / Window_Samples seconds (#1144). For an
    /// object without one, the application samples whatever it averages,
    /// spacing its readings that far apart, and passes each result here. On an
    /// object the server samples, a call is one more attempt in the window
    /// and doesn't move the server's schedule. A value may be
    /// a BOOLEAN (FALSE and TRUE count as 0 and 1), Signed, Unsigned,
    /// Enumerated or finite REAL; the object keeps its statistics in REAL
    /// (Clause 12.5). `None` records an attempt that produced no value, such
    /// as a failed read: it counts toward Attempted_Samples but not
    /// Valid_Samples. Another datatype, Double included, fails with PROPERTY /
    /// INVALID_DATA_TYPE and NaN or an infinity with PROPERTY /
    /// VALUE_OUT_OF_RANGE, and a refused sample counts as neither attempted
    /// nor valid. An unknown object fails with OBJECT / UNKNOWN_OBJECT and any
    /// object other than an Averaging object with OBJECT /
    /// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, as with
    /// [`BACnetServer::set_present_value_local`].
    ///
    /// Each call fills the next slot of the object's window, dropping the
    /// oldest once Window_Samples are held, and Minimum_Value, Maximum_Value,
    /// Average_Value, Attempted_Samples and Valid_Samples change together
    /// under the database lock; the server's COV processing runs once the
    /// lock is released. Averaging has no Table 13-1 row, so SubscribeCOV on
    /// it is refused, but SubscribeCOVProperty and
    /// SubscribeCOVPropertyMultiple are admitted: a numeric property is
    /// reported when it moves by the subscription's COV increment, or on any
    /// change when the subscription gives none (Table 13-1a). A move to or
    /// from the NaN or infinite value of an empty window is always reported,
    /// and staying at it never is. The report has no Status_Flags because the
    /// object has none. The Python binding exposes this as
    /// `BACnetServer.add_averaging_sample_local`.
    pub async fn add_averaging_sample_local(
        &self,
        oid: &ObjectIdentifier,
        sample: Option<PropertyValue>,
    ) -> Result<(), Error> {
        match sample {
            Some(value) => {
                self.write_local_as(oid, LocalWrite::ApplicationAveragingSample, value, None)
                    .await
            }
            None => {
                self.write_local_as(
                    oid,
                    LocalWrite::ApplicationAveragingMiss,
                    PropertyValue::Null,
                    None,
                )
                .await
            }
        }
    }

    /// Supply a Life Safety Point's or Zone's `Tracking_Value`, the live state
    /// the application derived, while the server holds the object.
    ///
    /// The value is an Enumerated naming a standard BACnetLifeSafetyState or
    /// one from the proprietary range 256..=65535. A reserved or larger number
    /// fails with PROPERTY / VALUE_OUT_OF_RANGE and another datatype with
    /// PROPERTY / INVALID_DATA_TYPE. An unknown object fails with OBJECT /
    /// UNKNOWN_OBJECT and any object other than a Life Safety Point or Zone
    /// with OBJECT / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, as with
    /// [`BACnetServer::set_present_value_local`]. Present_Value, Silenced and
    /// Operation_Expected are left as they are: the object derives nothing
    /// from Tracking_Value.
    ///
    /// While `Out_Of_Service` is TRUE the value replaces the one set aside for
    /// the return to service, and a client's simulated Tracking_Value keeps
    /// being served (#1108); the return to service then serves the latest
    /// application value and notifies its subscribers. In service, a change
    /// reaches SubscribeCOVProperty and SubscribeCOVPropertyMultiple
    /// subscribers of Tracking_Value through the Life Safety COV path once the
    /// database lock is released; whole-object SubscribeCOV reports don't
    /// carry it. The property stays read-only over the network in service.
    /// The Python binding exposes this as `BACnetServer.set_tracking_value_local`.
    pub async fn set_tracking_value_local(
        &self,
        oid: &ObjectIdentifier,
        value: PropertyValue,
    ) -> Result<(), Error> {
        self.write_local_as(oid, LocalWrite::ApplicationTrackingValue, value, None)
            .await
    }

    async fn write_local_as(
        &self,
        oid: &ObjectIdentifier,
        write: LocalWrite,
        value: PropertyValue,
        source: Option<crate::LocalCommandSource>,
    ) -> Result<(), Error> {
        self.active_network()?;
        // Only a property write can carry OBJECT_NAME, so only it needs the name
        // index kept in step.
        let renaming = matches!(
            write,
            LocalWrite::Property { property, .. } if property == PropertyIdentifier::OBJECT_NAME
        );
        let life_safety = crate::life_safety_cov::is_life_safety_object(*oid);
        let (exact_changes, staging_plans, schedule_cov) = {
            let mut db = self.db.write().await;
            let snapshots = crate::life_safety_cov::LifeSafetyCovSnapshots::capture_oid(&db, *oid);
            if db.get(oid).is_none() {
                return Err(Error::Protocol {
                    class: ErrorClass::OBJECT.to_raw() as u32,
                    code: ErrorCode::UNKNOWN_OBJECT.to_raw() as u32,
                });
            }
            if renaming {
                if let PropertyValue::CharacterString(ref new_name) = value {
                    db.check_name_available(oid, new_name)?;
                }
            }
            let mut audit = match write {
                LocalWrite::Property {
                    property,
                    array_index,
                    priority,
                } => {
                    // Device's recipient sink exclusively owns the old/new pair.
                    let recipient_sink = property
                        == PropertyIdentifier::AUDIT_NOTIFICATION_RECIPIENT
                        && db
                            .get_mut(oid)
                            .and_then(|object| object.device_authority_internal())
                            .is_some();
                    if recipient_sink {
                        None
                    } else {
                        let mut audit = audit_reporter::WriteAudit::local(
                            &self.config,
                            self.network
                                .as_ref()
                                .expect("running local mutation owns network"),
                            &self.notification_transactions,
                            &self.comm_state,
                            &db,
                        );
                        let encoded = audit_reporter::small_value(&value).unwrap_or_default();
                        if let Some(audit) = &mut audit {
                            audit.before(
                                &db,
                                WriteTarget {
                                    oid: *oid,
                                    property,
                                    array_index,
                                    priority,
                                    value: &encoded,
                                },
                            );
                        }
                        audit
                    }
                }
                LocalWrite::ApplicationPresentValue
                | LocalWrite::ApplicationControlledVariableValue
                | LocalWrite::ApplicationAveragingSample
                | LocalWrite::ApplicationAveragingMiss
                | LocalWrite::ApplicationTrackingValue => None,
            };
            let value = match write {
                LocalWrite::Property { property, .. } => {
                    crate::local_references::localize(&db, *oid, property, value)
                }
                _ => value,
            };
            let prepared = match write {
                LocalWrite::Property {
                    property,
                    array_index,
                    priority,
                } => {
                    let encoded = audit_reporter::small_value(&value).unwrap_or_default();
                    audit.as_mut().and_then(|audit| {
                        audit.commit_policy(
                            &mut db,
                            WriteTarget {
                                oid: *oid,
                                property,
                                array_index,
                                priority,
                                value: &encoded,
                            },
                            &value,
                        )
                    })
                }
                LocalWrite::ApplicationPresentValue
                | LocalWrite::ApplicationControlledVariableValue
                | LocalWrite::ApplicationAveragingSample
                | LocalWrite::ApplicationAveragingMiss
                | LocalWrite::ApplicationTrackingValue => None,
            };
            let command_origin =
                source.and_then(|source| crate::command_source::resolve_local(&db, source).ok());
            let result = prepared.unwrap_or_else(|| {
                let object = db.get_mut(oid).expect("existence checked above");
                match write {
                    LocalWrite::Property {
                        property,
                        array_index,
                        priority,
                    } => {
                        crate::device_view::check_executor_owned_write(*oid, property)?;
                        crate::command_source::write_target(
                            object,
                            property,
                            array_index,
                            value,
                            priority,
                            command_origin.as_ref(),
                        )
                    }
                    LocalWrite::ApplicationPresentValue => object.set_present_value_internal(value),
                    LocalWrite::ApplicationControlledVariableValue => {
                        object.set_controlled_variable_value_internal(value)
                    }
                    LocalWrite::ApplicationAveragingSample => {
                        object.add_averaging_sample_internal(Some(value))
                    }
                    LocalWrite::ApplicationAveragingMiss => {
                        object.add_averaging_sample_internal(None)
                    }
                    LocalWrite::ApplicationTrackingValue => {
                        object.set_tracking_value_internal(value)
                    }
                }
            });
            if let Err(error) = result {
                if let Some(audit) = &mut audit {
                    audit.failed(&mut db, &error);
                }
                return Err(error);
            }
            if let Some(audit) = &mut audit {
                audit.committed(&mut db);
            }
            if renaming {
                db.update_name_index(oid);
            }
            let staging_plans = Self::take_staging_plans(&mut db, std::slice::from_ref(oid));
            let changes = snapshots.changes(&db, std::slice::from_ref(oid));
            let capture = {
                let table = self.cov_table.read().await;
                if life_safety {
                    table.timed_capture_exact(&changes)
                } else {
                    table.timed_capture(*oid)
                }
            };
            capture.run(&db);
            let schedule_cov = crate::schedule::reevaluate_written(
                &mut db,
                std::slice::from_ref(oid),
                &self.cov_table,
            )
            .await;
            (changes, staging_plans, schedule_cov)
        };

        Self::fire_event_notifications_with_bindings(
            &EventDelivery {
                db: &self.db,
                network: self
                    .network
                    .as_ref()
                    .expect("running local mutation owns network"),
                comm_state: &self.comm_state,
                learned_routers: &self.learned_routers,
                notification_transactions: &self.notification_transactions,
                device_bindings: &self.device_bindings,
                suppressions: &self.event_suppressions,
                retry_timeout_ms: self.config.cov_retry_timeout_ms,
                local_apdu_capacity: self.config.max_apdu_length,
            },
            &self.cov_table,
            oid,
        )
        .await;
        if life_safety {
            for change in exact_changes {
                Self::fire_life_safety_cov_notifications(
                    &self.local_cov_context(),
                    &change.object_identifier,
                    &change.changed_properties,
                )
                .await;
            }
        } else {
            Self::fire_cov_notifications(&self.local_cov_context(), oid).await;
        }
        // Targets a written Schedule commanded on re-evaluation.
        Self::fire_post_write_cov_notifications(
            &self.local_cov_context(),
            &schedule_cov.coarse,
            &schedule_cov.life_safety,
        )
        .await;
        Self::execute_staging_plans(
            &self.local_event_delivery(),
            &self.local_cov_context(),
            staging_plans,
        )
        .await;
        Ok(())
    }

    /// Borrow the COV notification handles for a local mutation.
    fn local_cov_context(&self) -> CovNotifyContext<'_, T> {
        CovNotifyContext {
            db: &self.db,
            network: self
                .network
                .as_ref()
                .expect("running local mutation owns network"),
            cov_table: &self.cov_table,
            cov_in_flight: &self.cov_in_flight,
            notification_transactions: &self.notification_transactions,
            comm_state: &self.comm_state,
            config: &self.config,
        }
    }

    /// Borrow the EventNotification handles for a local mutation.
    fn local_event_delivery(&self) -> EventDelivery<'_, T> {
        EventDelivery {
            db: &self.db,
            network: self
                .network
                .as_ref()
                .expect("running local mutation owns network"),
            comm_state: &self.comm_state,
            learned_routers: &self.learned_routers,
            notification_transactions: &self.notification_transactions,
            device_bindings: &self.device_bindings,
            suppressions: &self.event_suppressions,
            retry_timeout_ms: self.config.cov_retry_timeout_ms,
            local_apdu_capacity: self.config.max_apdu_length,
        }
    }

    pub(super) async fn execute_initial_staging_plans(&self) {
        let staging_oids = {
            let database = self.db.read().await;
            database.find_by_type(ObjectType::STAGING)
        };
        let staging_plans = {
            let mut database = self.db.write().await;
            Self::take_staging_plans(&mut database, &staging_oids)
        };
        Self::execute_staging_plans(
            &self.local_event_delivery(),
            &self.local_cov_context(),
            staging_plans,
        )
        .await;
    }

    pub(super) fn take_staging_plans(
        db: &mut ObjectDatabase,
        oids: &[ObjectIdentifier],
    ) -> Vec<StagingWritePlan> {
        oids.iter()
            .filter_map(|oid| {
                db.get_mut(oid)
                    .and_then(|object| object.take_staging_write_plan_internal())
            })
            .collect()
    }

    /// Execute local Staging targets one mutation guard at a time.
    ///
    /// Every target mutation is generation-checked in the same database guard
    /// that applies it. Event/COV work runs only after that guard is released.
    pub(super) async fn execute_staging_plans(
        delivery: &EventDelivery<'_, T>,
        cov: &CovNotifyContext<'_, T>,
        plans: Vec<StagingWritePlan>,
    ) {
        let db = delivery.db;
        for plan in plans {
            let mut all_succeeded = true;
            for target in &plan.writes {
                enum TargetResult {
                    Applied,
                    Failed,
                    Stale,
                }

                let result = {
                    let mut database = db.write().await;
                    let current = database
                        .get(&plan.source)
                        .and_then(|source| source.staging_generation_internal())
                        == Some(plan.generation);
                    if !current {
                        TargetResult::Stale
                    } else {
                        let origin = crate::command_source::resolve_local(
                            &database,
                            crate::LocalCommandSource::Object(plan.source),
                        )
                        .ok();
                        match database.get_mut(&target.object_identifier) {
                            Some(object) => match crate::command_source::write_target(
                                object,
                                PropertyIdentifier::PRESENT_VALUE,
                                None,
                                PropertyValue::Enumerated(u32::from(target.active)),
                                Some(plan.priority),
                                origin.as_ref(),
                            ) {
                                Ok(()) => {
                                    // Timestamped references capture the
                                    // target change under this guard (#856).
                                    let capture = cov
                                        .cov_table
                                        .read()
                                        .await
                                        .timed_capture(target.object_identifier);
                                    capture.run(&database);
                                    TargetResult::Applied
                                }
                                Err(_) => TargetResult::Failed,
                            },
                            None => TargetResult::Failed,
                        }
                    }
                };

                match result {
                    TargetResult::Stale => break,
                    TargetResult::Failed => all_succeeded = false,
                    TargetResult::Applied => {
                        Self::fire_event_notifications_with_bindings(
                            delivery,
                            cov.cov_table,
                            &target.object_identifier,
                        )
                        .await;
                        Self::fire_cov_notifications(cov, &target.object_identifier).await;
                    }
                }
            }

            let reliability_changed = {
                let mut database = db.write().await;
                let changed = database.get_mut(&plan.source).is_some_and(|source| {
                    source.complete_staging_write_plan_internal(plan.generation, all_succeeded)
                });
                if changed {
                    let capture = cov.cov_table.read().await.timed_capture(plan.source);
                    capture.run(&database);
                }
                changed
            };
            if reliability_changed {
                Self::fire_event_notifications_with_bindings(delivery, cov.cov_table, &plan.source)
                    .await;
                Self::fire_cov_notifications(cov, &plan.source).await;
            }
        }
    }
}
