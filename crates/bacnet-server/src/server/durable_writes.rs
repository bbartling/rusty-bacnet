//! Staging writes whose new state an object saves first (#1270).
//!
//! A Notification Forwarder saves a written Recipient_List or
//! Subscribed_Recipients, and an Audit Log a Log_Enable change, before
//! serving it, and refuses the write if the save fails. So that the save
//! never runs while the database guard is held, a request that makes such a
//! write stages it first ([`DurableWrites`]): under the guard the object
//! queues the save, the request awaits it with the guard dropped, and then
//! runs as it always has, the object taking the saved state or refusing the
//! write. The request releases what it staged in the critical section that
//! makes the write.
//!
//! Other requests read and write the database while the save runs. One that
//! stages a write to the same object waits for the first to land; requests
//! that stage writes to several objects stage them in object order, so two
//! of them never wait on each other.
//!
//! [`DurableWrites`]: bacnet_objects::durable::DurableWrites

use std::sync::Arc;
use std::time::Duration;

use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::durable::{SaveWait, StageStep};
use bacnet_services::list_manipulation::ListElementRequest;
use bacnet_services::wpm::{WritePropertyMultipleCursor, WritePropertyMultipleEvent};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::Bytes;
use tokio::sync::RwLock;

use crate::handlers;

/// How long a request that found an object busy waits before it stages
/// again. The object drops a staged write its request has forgotten after a
/// while, so a retry gets through even then.
pub(super) const BUSY_RECHECK: Duration = Duration::from_secs(1);

/// One write a request is about to make to an object that may save it.
pub(super) struct DurableTarget {
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    array_index: Option<u32>,
    value: TargetValue,
}

enum TargetValue {
    /// The decoded written value, localized under the guard as the handler
    /// localizes it.
    Written(PropertyValue),
    /// The list an AddListElement (`remove` false) or RemoveListElement
    /// leaves, computed under the guard from the stored list.
    ListEdit { service_data: Bytes, remove: bool },
}

/// The object types whose bundled objects save a written state first.
///
/// An object type that takes up [`DurableWrites`] is listed here too, or
/// the server never stages its writes and they save in place under the
/// guard (see "Adding an object" in [`bacnet_objects::durable`]).
///
/// [`DurableWrites`]: bacnet_objects::durable::DurableWrites
fn may_save(oid: ObjectIdentifier) -> bool {
    matches!(
        oid.object_type(),
        ObjectType::NOTIFICATION_FORWARDER | ObjectType::AUDIT_LOG
    )
}

impl DurableTarget {
    /// The write a WriteProperty request makes, if its object may save it.
    pub(super) fn write_property(service_data: &[u8]) -> Vec<Self> {
        let Ok(request) = WritePropertyRequest::decode(service_data) else {
            return Vec::new();
        };
        if !may_save(request.object_identifier) {
            return Vec::new();
        }
        let Ok(value) = handlers::decode_write_property_value(
            request.property_identifier,
            request.property_array_index,
            &request.property_value,
        ) else {
            return Vec::new();
        };
        vec![Self {
            oid: request.object_identifier,
            property: request.property_identifier,
            array_index: request.property_array_index,
            value: TargetValue::Written(value),
        }]
    }

    /// The writes a WritePropertyMultiple request makes to objects that may
    /// save them, in object order and then request order. [`stage`] stages
    /// the first of each object's writes that the object takes; a later one
    /// saves in place.
    pub(super) fn write_property_multiple(service_data: &[u8]) -> Vec<Self> {
        let mut cursor = WritePropertyMultipleCursor::new(service_data);
        let mut targets: Vec<Self> = Vec::new();
        while let Ok(Some(event)) = cursor.next_event() {
            let WritePropertyMultipleEvent::WriteAttempt(attempt) = event else {
                continue;
            };
            let reference = attempt.reference;
            let oid = reference.object_identifier;
            if !may_save(oid) {
                continue;
            }
            let property = PropertyIdentifier::from_raw(reference.property_identifier);
            if let Ok(value) = handlers::decode_write_property_value(
                property,
                reference.property_array_index,
                &attempt.value,
            ) {
                targets.push(Self {
                    oid,
                    property,
                    array_index: reference.property_array_index,
                    value: TargetValue::Written(value),
                });
            }
        }
        targets.sort_by_key(|target| {
            (
                target.oid.object_type().to_raw(),
                target.oid.instance_number(),
            )
        });
        targets
    }

    /// The write an AddListElement or RemoveListElement request makes, if
    /// its object may save it.
    pub(super) fn list_element(service_data: &Bytes, remove: bool) -> Vec<Self> {
        let Ok(request) = ListElementRequest::decode(service_data) else {
            return Vec::new();
        };
        if !may_save(request.object_identifier) {
            return Vec::new();
        }
        vec![Self {
            oid: request.object_identifier,
            property: request.property_identifier,
            array_index: request.property_array_index,
            value: TargetValue::ListEdit {
                service_data: service_data.clone(),
                remove,
            },
        }]
    }

    /// A local property write, if its object may save it.
    pub(super) fn local(
        oid: ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: &PropertyValue,
    ) -> Vec<Self> {
        if !may_save(oid) {
            return Vec::new();
        }
        vec![Self {
            oid,
            property,
            array_index,
            value: TargetValue::Written(value.clone()),
        }]
    }

    fn value_in(&self, db: &ObjectDatabase) -> Option<PropertyValue> {
        match &self.value {
            TargetValue::Written(value) => Some(crate::local_references::localize(
                db,
                self.oid,
                self.property,
                value.clone(),
            )),
            TargetValue::ListEdit {
                service_data,
                remove,
            } => handlers::edited_list_value(db, service_data, *remove),
        }
    }
}

/// The objects a request staged writes on, each with the wait its stage
/// gave, which shows the object the stage is this request's.
#[must_use = "release staged writes in the critical section that makes them"]
pub(super) struct StagedWrites(Vec<(ObjectIdentifier, SaveWait)>);

impl StagedWrites {
    /// Release every staged write. Call it under the guard of the critical
    /// section that made the writes, after the writes. An object whose
    /// staged write was not taken saves the state it serves at once.
    pub(super) fn release(self, db: &mut ObjectDatabase) {
        for (oid, staged) in self.0 {
            if let Some(writes) = db
                .get_mut(&oid)
                .and_then(|object| object.durable_writes_internal())
            {
                writes.release_staged_write(&staged);
            }
        }
    }
}

/// Wait for a staged save with the database guard dropped.
///
/// The save runs on the object's own writer thread, which Tokio cannot see.
/// Awaiting it directly would leave the runtime looking idle, and under a
/// paused test clock (`tokio::time::pause`) an idle runtime jumps virtual
/// time to the next timer: request timeouts would fire while the save was
/// still running. The wait therefore runs on the blocking pool, which keeps a
/// paused clock where it is until the save is done. A pool thread is held
/// only while a staged save is in flight, at most one per object.
pub(super) async fn saved(wait: SaveWait) {
    if wait.is_ready() {
        return;
    }
    let blocking = wait.clone();
    if tokio::task::spawn_blocking(move || blocking.block())
        .await
        .is_err()
    {
        wait.await;
    }
}

/// Stage `targets` and wait for their saves without holding the database
/// guard. `targets` come in object order, so two requests never wait on each
/// other.
pub(super) async fn stage(
    db: &Arc<RwLock<ObjectDatabase>>,
    targets: Vec<DurableTarget>,
) -> StagedWrites {
    let mut staged = Vec::new();
    for target in targets {
        // One staged write per object: its request's later writes to the
        // object save in place.
        if staged.iter().any(|(oid, _)| *oid == target.oid) {
            continue;
        }
        loop {
            let step = {
                let mut guard = db.write().await;
                let Some(value) = target.value_in(&guard) else {
                    break;
                };
                let Some(writes) = guard
                    .get_mut(&target.oid)
                    .and_then(|object| object.durable_writes_internal())
                else {
                    break;
                };
                writes.stage_write(target.property, target.array_index, &value)
            };
            match step {
                StageStep::Staged(wait) => {
                    saved(wait.clone()).await;
                    staged.push((target.oid, wait));
                    break;
                }
                StageStep::Busy(wait) => {
                    let _ = tokio::time::timeout(BUSY_RECHECK, wait).await;
                }
                StageStep::Skip => break,
            }
        }
    }
    StagedWrites(staged)
}
