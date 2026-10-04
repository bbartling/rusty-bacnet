//! Staging writes whose new state an object saves first (#1270).
//!
//! A Notification Forwarder saves a written Recipient_List or
//! Subscribed_Recipients, a Notification Class a written Recipient_List
//! (#1315), and an Audit Log a Log_Enable or Buffer_Size change, before
//! serving it, and refuses the write if the save fails. So that the save
//! never runs while the database guard is held, a request that makes such a
//! write stages it first ([`DurableWrites`]): under the guard the object
//! queues the save, the request awaits it with the guard dropped, and then
//! runs as it always has, the object taking the saved state or refusing the
//! write. The request releases what it staged in the critical section that
//! makes the write. An application's Audit Log purge (#1238) is staged the
//! same way.
//!
//! A request stages once per object, handing it all of the request's writes
//! to it in order. An Audit Log folds a WritePropertyMultiple's Log_Enable
//! and Buffer_Size writes into one save; a forwarder or a Notification Class
//! stages the first write it takes, and the request's later writes to it
//! save in place.
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
use bacnet_objects::durable::{PendingWrite, SaveWait, StageStep};
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

/// One change a request is about to make to an object that may save it.
pub(super) struct DurableTarget {
    oid: ObjectIdentifier,
    change: Change,
}

enum Change {
    /// A property write.
    Write {
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: TargetValue,
    },
    /// The application's purge of the object's records.
    Purge,
}

enum TargetValue {
    /// The decoded written value, localized under the guard as the handler
    /// localizes it.
    Written(PropertyValue),
    /// The list an AddListElement (`remove` false) or RemoveListElement
    /// leaves, computed under the guard from the stored list.
    ListEdit { service_data: Bytes, remove: bool },
}

/// Whether a bundled object of `oid`'s type may save a write of `property`
/// first. A Notification Class saves only its Recipient_List; a forwarder
/// and an Audit Log decide for themselves, any property.
///
/// An object type that takes up [`DurableWrites`] is listed here too, or
/// the server never stages its writes and they save in place under the
/// guard (see "Adding an object" in [`bacnet_objects::durable`]).
///
/// [`DurableWrites`]: bacnet_objects::durable::DurableWrites
fn may_save(oid: ObjectIdentifier, property: PropertyIdentifier) -> bool {
    match oid.object_type() {
        ObjectType::NOTIFICATION_FORWARDER | ObjectType::AUDIT_LOG => true,
        ObjectType::NOTIFICATION_CLASS => property == PropertyIdentifier::RECIPIENT_LIST,
        _ => false,
    }
}

/// Whether a bundled object of `oid`'s type holds `property` as a
/// BACnetLIST. No type [`may_save`] admits departs from the standard
/// classification, so a value decodes here as the handler decodes it after
/// asking the object.
fn held_as_list(oid: ObjectIdentifier, property: PropertyIdentifier) -> bool {
    bacnet_objects::traits::standard_list_property(oid.object_type(), property)
}

impl DurableTarget {
    /// The write a WriteProperty request makes, if its object may save it.
    pub(super) fn write_property(service_data: &[u8]) -> Vec<Self> {
        let Ok(request) = WritePropertyRequest::decode(service_data) else {
            return Vec::new();
        };
        if !may_save(request.object_identifier, request.property_identifier) {
            return Vec::new();
        }
        let Ok(value) = handlers::decode_write_property_value(
            request.property_identifier,
            request.property_array_index,
            held_as_list(request.object_identifier, request.property_identifier),
            &request.property_value,
        ) else {
            return Vec::new();
        };
        vec![Self::write(
            request.object_identifier,
            request.property_identifier,
            request.property_array_index,
            TargetValue::Written(value),
        )]
    }

    fn write(
        oid: ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: TargetValue,
    ) -> Self {
        Self {
            oid,
            change: Change::Write {
                property,
                array_index,
                value,
            },
        }
    }

    /// The writes a WritePropertyMultiple request makes to objects that may
    /// save them, in object order and then request order. [`stage`] hands
    /// each object its writes together.
    pub(super) fn write_property_multiple(service_data: &[u8]) -> Vec<Self> {
        let mut cursor = WritePropertyMultipleCursor::new(service_data);
        let mut targets: Vec<Self> = Vec::new();
        while let Ok(Some(event)) = cursor.next_event() {
            let WritePropertyMultipleEvent::WriteAttempt(attempt) = event else {
                continue;
            };
            let reference = attempt.reference;
            let oid = reference.object_identifier;
            let property = PropertyIdentifier::from_raw(reference.property_identifier);
            if !may_save(oid, property) {
                continue;
            }
            if let Ok(value) = handlers::decode_write_property_value(
                property,
                reference.property_array_index,
                held_as_list(oid, property),
                &attempt.value,
            ) {
                targets.push(Self::write(
                    oid,
                    property,
                    reference.property_array_index,
                    TargetValue::Written(value),
                ));
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
        if !may_save(request.object_identifier, request.property_identifier) {
            return Vec::new();
        }
        vec![Self::write(
            request.object_identifier,
            request.property_identifier,
            request.property_array_index,
            TargetValue::ListEdit {
                service_data: service_data.clone(),
                remove,
            },
        )]
    }

    /// A local property write, if its object may save it.
    pub(super) fn local(
        oid: ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: &PropertyValue,
    ) -> Vec<Self> {
        if !may_save(oid, property) {
            return Vec::new();
        }
        vec![Self::write(
            oid,
            property,
            array_index,
            TargetValue::Written(value.clone()),
        )]
    }

    /// The application's purge of `oid`, if it names an Audit Log, the one
    /// object type that purges.
    pub(super) fn purge(oid: ObjectIdentifier) -> Vec<Self> {
        if oid.object_type() != ObjectType::AUDIT_LOG {
            return Vec::new();
        }
        vec![Self {
            oid,
            change: Change::Purge,
        }]
    }
}

impl TargetValue {
    /// The value the write leaves, worked out under the guard as the handler
    /// works it out. `None` when a list edit cannot be worked out.
    fn resolve(
        &self,
        db: &ObjectDatabase,
        oid: ObjectIdentifier,
        property: PropertyIdentifier,
    ) -> Option<PropertyValue> {
        match self {
            Self::Written(value) => Some(crate::local_references::localize(
                db,
                oid,
                property,
                value.clone(),
            )),
            Self::ListEdit {
                service_data,
                remove,
            } => handlers::edited_list_value(db, service_data, *remove),
        }
    }
}

/// Stage one object's changes under the guard: `group` holds the request's
/// changes to that object, in request order. `None` when there is nothing
/// to stage: the object is gone or does not save, or its first written list
/// cannot be worked out. The writes go to the object together, so it can
/// fold them into one save.
fn stage_group(group: &[DurableTarget], db: &mut ObjectDatabase) -> Option<StageStep> {
    let first = group.first()?;
    let oid = first.oid;
    if matches!(first.change, Change::Purge) {
        return Some(db.get_mut(&oid)?.durable_writes_internal()?.stage_purge());
    }
    let mut writes = Vec::with_capacity(group.len());
    for target in group {
        let Change::Write {
            property,
            array_index,
            value,
        } = &target.change
        else {
            break;
        };
        // The request stops at a list it cannot edit; stage what comes first.
        let Some(value) = value.resolve(db, oid, *property) else {
            break;
        };
        writes.push(PendingWrite {
            property: *property,
            array_index: *array_index,
            value,
        });
    }
    if writes.is_empty() {
        return None;
    }
    Some(
        db.get_mut(&oid)?
            .durable_writes_internal()?
            .stage_writes(&writes),
    )
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

/// Requests that found an object busy, per database (by address), so a test
/// can see a request reach its wait for another request's staged save.
#[cfg(test)]
static BUSY_WAITS: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

/// Note that a request on `db` found an object busy and is about to wait.
/// Only tests count it; otherwise this does nothing.
pub(super) fn note_busy(db: &Arc<RwLock<ObjectDatabase>>) {
    #[cfg(test)]
    {
        let key = Arc::as_ptr(db) as usize;
        let mut counts = BUSY_WAITS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match counts.iter_mut().find(|(at, _)| *at == key) {
            Some((_, count)) => *count += 1,
            None => counts.push((key, 1)),
        }
    }
    #[cfg(not(test))]
    let _ = db;
}

/// How many times requests on `db` have found an object busy.
#[cfg(test)]
pub(super) fn busy_waits(db: &Arc<RwLock<ObjectDatabase>>) -> usize {
    let key = Arc::as_ptr(db) as usize;
    BUSY_WAITS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(at, _)| *at == key)
        .map_or(0, |(_, count)| *count)
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

/// Settle every staged write in `db` once no request is left to take or
/// release one: `stop()` calls this after joining its requests (#1363).
/// Each object drops what it holds staged and puts storage back to the state
/// it serves, and the saves are awaited off the guard, so storage matches
/// what the objects serve when `stop()` returns.
///
/// A second pass takes what the first waited for: an Audit Log batch whose
/// commit was still running, which the log takes once it has landed.
///
/// An application holding the database is not waited for, as with the
/// Command runs `stop()` ends: the objects then settle from a task once it
/// lets go, and in any case put storage back when they are dropped.
pub(super) async fn settle_forgotten(db: &Arc<RwLock<ObjectDatabase>>) {
    for _ in 0..2 {
        let waits = match db.try_write() {
            Ok(mut db) => settle_all(&mut db),
            Err(_) => {
                let db = Arc::clone(db);
                tokio::spawn(async move {
                    settle_all(&mut *db.write().await);
                });
                return;
            }
        };
        if waits.is_empty() {
            return;
        }
        for wait in waits {
            saved(wait).await;
        }
    }
}

/// Settle every object's forgotten staged writes; the waits for the saves
/// that are still to run.
fn settle_all(db: &mut ObjectDatabase) -> Vec<SaveWait> {
    let mut waits = Vec::new();
    db.for_each_object_mut(|_, object| {
        if let Some(wait) = object
            .durable_writes_internal()
            .and_then(|writes| writes.settle_forgotten_writes())
            .filter(|wait| !wait.is_ready())
        {
            waits.push(wait);
        }
    });
    waits
}

/// Stage `targets` and wait for their saves without holding the database
/// guard. `targets` come in object order, so two requests never wait on each
/// other.
pub(super) async fn stage(
    db: &Arc<RwLock<ObjectDatabase>>,
    targets: Vec<DurableTarget>,
) -> StagedWrites {
    let mut staged = Vec::new();
    // Each object stages once, with all of the request's changes to it.
    for group in targets.chunk_by(|a, b| a.oid == b.oid) {
        loop {
            let step = {
                let mut guard = db.write().await;
                stage_group(group, &mut guard)
            };
            match step {
                Some(StageStep::Staged(wait)) => {
                    saved(wait.clone()).await;
                    staged.push((group[0].oid, wait));
                    break;
                }
                Some(StageStep::Busy(wait)) => {
                    note_busy(db);
                    let _ = tokio::time::timeout(BUSY_RECHECK, wait).await;
                }
                Some(StageStep::Skip) | None => break,
            }
        }
    }
    StagedWrites(staged)
}
