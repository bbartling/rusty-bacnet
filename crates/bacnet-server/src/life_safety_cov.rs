//! Exact readback snapshots for server-owned Life Safety COV mutation paths.

use bacnet_objects::database::ObjectDatabase;
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};

/// The COV surface a Point and a Zone share, Tracking_Value included.
const PROPERTIES: [PropertyIdentifier; 5] = [
    PropertyIdentifier::PRESENT_VALUE,
    PropertyIdentifier::TRACKING_VALUE,
    PropertyIdentifier::SILENCED,
    PropertyIdentifier::OPERATION_EXPECTED,
    PropertyIdentifier::STATUS_FLAGS,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LifeSafetyCovChange {
    pub(crate) object_identifier: ObjectIdentifier,
    pub(crate) changed_properties: Vec<PropertyIdentifier>,
}

impl LifeSafetyCovChange {
    pub(crate) fn new(
        object_identifier: ObjectIdentifier,
        changed_properties: Vec<PropertyIdentifier>,
    ) -> Option<Self> {
        (!changed_properties.is_empty()).then_some(Self {
            object_identifier,
            changed_properties,
        })
    }
}

#[derive(Debug, Clone)]
struct ObjectSnapshot {
    object_identifier: ObjectIdentifier,
    values: Vec<(PropertyIdentifier, PropertyValue)>,
}

/// Pre-mutation readback for the exact Life Safety COV surface.
#[derive(Debug, Clone, Default)]
pub(crate) struct LifeSafetyCovSnapshots {
    objects: Vec<ObjectSnapshot>,
    held: std::collections::HashSet<ObjectIdentifier>,
}

pub(crate) fn is_life_safety_object(object_identifier: ObjectIdentifier) -> bool {
    matches!(
        object_identifier.object_type(),
        ObjectType::LIFE_SAFETY_POINT | ObjectType::LIFE_SAFETY_ZONE
    )
}

fn properties_for(object_identifier: ObjectIdentifier) -> Option<&'static [PropertyIdentifier]> {
    is_life_safety_object(object_identifier).then_some(&PROPERTIES)
}

impl LifeSafetyCovSnapshots {
    pub(crate) fn capture_oid(db: &ObjectDatabase, object_identifier: ObjectIdentifier) -> Self {
        Self::capture_oids(db, [object_identifier])
    }

    pub(crate) fn capture_write_property(db: &ObjectDatabase, service_data: &[u8]) -> Self {
        WritePropertyRequest::decode(service_data)
            .map(|request| Self::capture_oid(db, request.object_identifier))
            .unwrap_or_default()
    }

    /// Capture a Life Safety object immediately before its first WPM attempt.
    pub(crate) fn capture_before_write(
        &mut self,
        db: &ObjectDatabase,
        object_identifier: ObjectIdentifier,
    ) {
        if self
            .objects
            .iter()
            .any(|snapshot| snapshot.object_identifier == object_identifier)
        {
            return;
        }
        if let Some(snapshot) = Self::capture_oid(db, object_identifier).objects.pop() {
            self.objects.push(snapshot);
        }
    }

    pub(crate) fn changes(
        &self,
        db: &ObjectDatabase,
        affected_oids: &[ObjectIdentifier],
    ) -> Vec<LifeSafetyCovChange> {
        self.objects
            .iter()
            .filter(|snapshot| affected_oids.contains(&snapshot.object_identifier))
            .filter_map(|snapshot| {
                let object = db.get(&snapshot.object_identifier)?;
                let changed_properties = snapshot
                    .values
                    .iter()
                    .filter_map(|(property, previous)| {
                        object
                            .read_property(*property, None)
                            .is_ok_and(|current| current != *previous)
                            .then_some(*property)
                    })
                    .collect();
                LifeSafetyCovChange::new(snapshot.object_identifier, changed_properties)
            })
            .collect()
    }

    pub(crate) fn capture_oids(
        db: &ObjectDatabase,
        object_identifiers: impl IntoIterator<Item = ObjectIdentifier>,
    ) -> Self {
        let mut snapshots = Self::default();
        for object_identifier in object_identifiers {
            snapshots.capture(db, object_identifier);
        }
        snapshots
    }

    /// Add one object's pre-mutation state unless it is already held or is not
    /// a Life Safety object.
    pub(crate) fn capture(&mut self, db: &ObjectDatabase, object_identifier: ObjectIdentifier) {
        let Some(properties) = properties_for(object_identifier) else {
            return;
        };
        let Some(object) = db.get(&object_identifier) else {
            return;
        };
        if !self.held.insert(object_identifier) {
            return;
        }
        let values = properties
            .iter()
            .filter_map(|property| {
                object
                    .read_property(*property, None)
                    .ok()
                    .map(|value| (*property, value))
            })
            .collect();
        self.objects.push(ObjectSnapshot {
            object_identifier,
            values,
        });
    }
}
