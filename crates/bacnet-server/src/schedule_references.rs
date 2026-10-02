//! Schedule references that name this device (#1122).
//!
//! Clause 12.24.10 lets a Schedule whose List_Of_Object_Property_References
//! is limited to its own device refuse a reference to an object elsewhere.
//! The Schedule object here has that profile, but it can't tell which Device
//! holds it, so it refuses every member that carries a Device identifier. A
//! member whose Device identifier is this device's points inside the device,
//! so refusing it would be stricter than the clause allows. The server knows
//! the local Device (`local_device::selected_device`, under the same database
//! guard as the write), so it rewrites such a member as the local reference it
//! denotes before the Schedule sees it: WriteProperty, WritePropertyMultiple,
//! `write_local`, and the elements of AddListElement and RemoveListElement.
//! A member naming any other device keeps its Device identifier, and the
//! Schedule refuses it. The Schedule stores, and a read returns, the local
//! form, so a member written with and without the identifier is one member.

use bacnet_encoding::constructed::{
    decode_device_object_property_reference, encode_device_object_property_reference,
};
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::BytesMut;

/// Whether `property` of an object of `object_type` holds references that
/// this server localizes: a Schedule's List_Of_Object_Property_References.
pub(crate) fn localizes(object_type: ObjectType, property: PropertyIdentifier) -> bool {
    object_type == ObjectType::SCHEDULE
        && property == PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES
}

/// The Device a member must name to be local: the selected local Device,
/// when its instance is concrete. A reference to the wildcard instance names
/// no particular device.
pub(crate) fn local_device(db: &ObjectDatabase) -> Option<ObjectIdentifier> {
    crate::local_device::selected_device(db)
        .filter(|device| device.instance_number() != ObjectIdentifier::WILDCARD_INSTANCE)
}

/// Drop `member`'s Device identifier if it names `local`.
pub(crate) fn localize_member(
    member: &mut BACnetDeviceObjectPropertyReference,
    local: Option<ObjectIdentifier>,
) {
    if member.device_identifier.is_some() && member.device_identifier == local {
        member.device_identifier = None;
    }
}

/// A value written to `property` of `oid`, with every member that names the
/// local Device in its local form. Other properties, and values that are
/// not raw member bytes, pass through unchanged for the object to judge.
pub(crate) fn localize(
    db: &ObjectDatabase,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> PropertyValue {
    if !localizes(oid.object_type(), property) {
        return value;
    }
    let Some(local) = local_device(db) else {
        return value;
    };
    let chunk = |value| match value {
        PropertyValue::ApplicationData(bytes) => {
            PropertyValue::ApplicationData(localize_bytes(&bytes, local))
        }
        other => other,
    };
    match value {
        // The shape a read returns: one chunk of members per element.
        PropertyValue::List(elements) => {
            PropertyValue::List(elements.into_iter().map(chunk).collect())
        }
        value => chunk(value),
    }
}

/// Re-encode each member of `bytes` that names `local` without its Device
/// identifier. Decoding stops at the first member that doesn't decode; it and
/// everything after it pass on as written, so the object refuses that member
/// with its own error and position.
fn localize_bytes(bytes: &[u8], local: ObjectIdentifier) -> Vec<u8> {
    let mut localized = BytesMut::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        let Ok((mut member, end)) = decode_device_object_property_reference(bytes, offset) else {
            localized.extend_from_slice(&bytes[offset..]);
            break;
        };
        if member.device_identifier == Some(local) {
            localize_member(&mut member, Some(local));
            encode_device_object_property_reference(&mut localized, &member);
        } else {
            localized.extend_from_slice(&bytes[offset..end]);
        }
        offset = end;
    }
    localized.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_objects::device::{DeviceConfig, DeviceObject};
    use bacnet_objects::schedule::ScheduleObject;

    fn device(instance: u32) -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap()
    }

    fn member(
        instance: u32,
        device: Option<ObjectIdentifier>,
    ) -> BACnetDeviceObjectPropertyReference {
        BACnetDeviceObjectPropertyReference {
            object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, instance).unwrap(),
            property_identifier: PropertyIdentifier::PRESENT_VALUE.to_raw(),
            property_array_index: None,
            device_identifier: device,
        }
    }

    fn encoded(members: &[BACnetDeviceObjectPropertyReference]) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        for member in members {
            encode_device_object_property_reference(&mut bytes, member);
        }
        bytes.to_vec()
    }

    fn database(instance: u32) -> ObjectDatabase {
        let mut db = ObjectDatabase::new();
        db.add(Box::new(
            DeviceObject::new(DeviceConfig {
                instance,
                ..DeviceConfig::default()
            })
            .unwrap(),
        ))
        .unwrap();
        db.add(Box::new(
            ScheduleObject::new(1, "SCH-1", PropertyValue::Real(0.0)).unwrap(),
        ))
        .unwrap();
        db
    }

    const LIST: PropertyIdentifier = PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES;

    fn schedule() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::SCHEDULE, 1).unwrap()
    }

    #[test]
    fn only_members_naming_the_local_device_lose_their_device() {
        let db = database(7);
        let written = encoded(&[
            member(1, Some(device(7))),
            member(2, None),
            member(3, Some(device(9))),
        ]);
        let expected = encoded(&[member(1, None), member(2, None), member(3, Some(device(9)))]);
        assert_eq!(
            localize(
                &db,
                schedule(),
                LIST,
                PropertyValue::ApplicationData(written)
            ),
            PropertyValue::ApplicationData(expected)
        );
        // The shape a read returns, one chunk per element.
        assert_eq!(
            localize(
                &db,
                schedule(),
                LIST,
                PropertyValue::List(vec![
                    PropertyValue::ApplicationData(encoded(&[member(1, Some(device(7)))])),
                    PropertyValue::ApplicationData(encoded(&[member(3, Some(device(9)))])),
                ])
            ),
            PropertyValue::List(vec![
                PropertyValue::ApplicationData(encoded(&[member(1, None)])),
                PropertyValue::ApplicationData(encoded(&[member(3, Some(device(9)))])),
            ])
        );
    }

    #[test]
    fn a_malformed_member_and_what_follows_pass_on_as_written() {
        let db = database(7);
        let local = encoded(&[member(2, Some(device(7)))]);
        // An object identifier without its property, then a local member.
        let rest = [local[..5].to_vec(), local].concat();
        let written = [encoded(&[member(1, Some(device(7)))]), rest.clone()].concat();
        let expected = [encoded(&[member(1, None)]), rest].concat();
        assert_eq!(
            localize(
                &db,
                schedule(),
                LIST,
                PropertyValue::ApplicationData(written)
            ),
            PropertyValue::ApplicationData(expected)
        );
    }

    #[test]
    fn other_targets_and_devices_are_left_alone() {
        let local = encoded(&[member(1, Some(device(7)))]);
        let value = || PropertyValue::ApplicationData(local.clone());
        // Another property, another object type, and no Device object.
        let db = database(7);
        let av = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap();
        assert_eq!(
            localize(&db, schedule(), PropertyIdentifier::DESCRIPTION, value()),
            value()
        );
        assert_eq!(localize(&db, av, LIST, value()), value());
        let mut empty = ObjectDatabase::new();
        empty
            .add(Box::new(
                ScheduleObject::new(1, "SCH-1", PropertyValue::Real(0.0)).unwrap(),
            ))
            .unwrap();
        assert_eq!(localize(&empty, schedule(), LIST, value()), value());
        // A Device at the wildcard instance names no device in particular.
        let wildcard = database(ObjectIdentifier::WILDCARD_INSTANCE);
        assert_eq!(local_device(&wildcard), None);
        let named = encoded(&[member(1, Some(device(ObjectIdentifier::WILDCARD_INSTANCE)))]);
        assert_eq!(
            localize(
                &wildcard,
                schedule(),
                LIST,
                PropertyValue::ApplicationData(named.clone())
            ),
            PropertyValue::ApplicationData(named)
        );
    }
}
