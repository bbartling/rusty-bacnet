//! References that name this device (#1122, #1136).
//!
//! Two properties hold references this server keeps inside its own device: a
//! Schedule's List_Of_Object_Property_References (Clause 12.24.10) and a
//! Staging object's Target_References (Clause 12.62.14). For a property with
//! that limit, both clauses permit refusing a reference to an object in some
//! other device, and nothing more. Neither object can tell which Device holds
//! it, so each refuses every member that carries a Device identifier. A member
//! whose Device identifier is this device's points inside the device, so
//! refusing it would be stricter than the clauses allow. The server knows the
//! local Device (`local_device::selected_device`, under the same database
//! guard as the write), so it rewrites such a member as the local reference it
//! denotes before the object sees it: WriteProperty, WritePropertyMultiple,
//! `write_local`, and, for the Schedule's list, the elements of AddListElement
//! and RemoveListElement. A member naming any other device keeps its Device
//! identifier, and the object refuses it. The object stores, and a read
//! returns, the local form, so a member written with and without the
//! identifier is one member.

use bacnet_encoding::constructed::{
    decode_device_object_property_reference, decode_device_object_reference,
    encode_device_object_property_reference, encode_device_object_reference,
};
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, BACnetDeviceObjectReference};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::BytesMut;

/// A reference whose optional Device member the server may drop, with the
/// shared codec for its wire form.
pub(crate) trait DeviceQualified: Sized {
    /// Decode one reference at `offset`: the reference and the offset after it.
    fn decode(bytes: &[u8], offset: usize) -> Result<(Self, usize), Error>;
    /// Append the reference's encoding to `buf`.
    fn encode(&self, buf: &mut BytesMut);
    /// The optional Device member.
    fn device_mut(&mut self) -> &mut Option<ObjectIdentifier>;
}

impl DeviceQualified for BACnetDeviceObjectPropertyReference {
    fn decode(bytes: &[u8], offset: usize) -> Result<(Self, usize), Error> {
        decode_device_object_property_reference(bytes, offset)
    }

    fn encode(&self, buf: &mut BytesMut) {
        encode_device_object_property_reference(buf, self);
    }

    fn device_mut(&mut self) -> &mut Option<ObjectIdentifier> {
        &mut self.device_identifier
    }
}

impl DeviceQualified for BACnetDeviceObjectReference {
    fn decode(bytes: &[u8], offset: usize) -> Result<(Self, usize), Error> {
        decode_device_object_reference(bytes, offset)
    }

    fn encode(&self, buf: &mut BytesMut) {
        encode_device_object_reference(buf, self);
    }

    fn device_mut(&mut self) -> &mut Option<ObjectIdentifier> {
        &mut self.device_identifier
    }
}

/// Rewrites a run of encoded members so none names the given Device.
type Rewrite = fn(&[u8], ObjectIdentifier) -> Vec<u8>;

/// The rewrite for `property` of an object of `object_type`, if the server
/// localizes its references: a Schedule's List_Of_Object_Property_References
/// or a Staging object's Target_References.
fn rewrite(object_type: ObjectType, property: PropertyIdentifier) -> Option<Rewrite> {
    match (object_type, property) {
        (ObjectType::SCHEDULE, PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES) => {
            Some(localize_bytes::<BACnetDeviceObjectPropertyReference>)
        }
        (ObjectType::STAGING, PropertyIdentifier::TARGET_REFERENCES) => {
            Some(localize_bytes::<BACnetDeviceObjectReference>)
        }
        _ => None,
    }
}

/// The Device a member must name to be local: the selected local Device,
/// when its instance is concrete. A reference to the wildcard instance names
/// no particular device.
pub(crate) fn local_device(db: &ObjectDatabase) -> Option<ObjectIdentifier> {
    crate::local_device::selected_device(db)
        .filter(|device| device.instance_number() != ObjectIdentifier::WILDCARD_INSTANCE)
}

/// Drop `member`'s Device identifier if it names `local`.
pub(crate) fn localize_member<R: DeviceQualified>(member: &mut R, local: Option<ObjectIdentifier>) {
    let device = member.device_mut();
    if device.is_some() && *device == local {
        *device = None;
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
    let Some(rewrite) = rewrite(oid.object_type(), property) else {
        return value;
    };
    let Some(local) = local_device(db) else {
        return value;
    };
    let chunk = |value| match value {
        PropertyValue::ApplicationData(bytes) => {
            PropertyValue::ApplicationData(rewrite(&bytes, local))
        }
        other => other,
    };
    match value {
        // The shape a read returns, and a whole array as the handler splits
        // it: one chunk of members per element.
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
fn localize_bytes<R: DeviceQualified>(bytes: &[u8], local: ObjectIdentifier) -> Vec<u8> {
    let mut localized = BytesMut::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        let (mut member, end) = match R::decode(bytes, offset) {
            Ok((member, end)) if end > offset => (member, end),
            _ => {
                localized.extend_from_slice(&bytes[offset..]);
                break;
            }
        };
        if *member.device_mut() == Some(local) {
            localize_member(&mut member, Some(local));
            member.encode(&mut localized);
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

    fn target(instance: u32, device: Option<ObjectIdentifier>) -> BACnetDeviceObjectReference {
        BACnetDeviceObjectReference {
            device_identifier: device,
            object_identifier: ObjectIdentifier::new(ObjectType::BINARY_OUTPUT, instance).unwrap(),
        }
    }

    fn encoded<R: DeviceQualified>(members: &[R]) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        for member in members {
            member.encode(&mut bytes);
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
    const TARGETS: PropertyIdentifier = PropertyIdentifier::TARGET_REFERENCES;

    fn schedule() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::SCHEDULE, 1).unwrap()
    }

    fn staging() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::STAGING, 1).unwrap()
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
    fn staging_targets_naming_the_local_device_lose_their_device() {
        // Device 7 has no Staging object; the rewrite keys on the identifier.
        let db = database(7);
        // A whole array, one element per chunk, as the handler splits it.
        assert_eq!(
            localize(
                &db,
                staging(),
                TARGETS,
                PropertyValue::List(vec![
                    PropertyValue::ApplicationData(encoded(&[target(1, Some(device(7)))])),
                    PropertyValue::ApplicationData(encoded(&[target(2, None)])),
                    PropertyValue::ApplicationData(encoded(&[target(3, Some(device(9)))])),
                ])
            ),
            PropertyValue::List(vec![
                PropertyValue::ApplicationData(encoded(&[target(1, None)])),
                PropertyValue::ApplicationData(encoded(&[target(2, None)])),
                PropertyValue::ApplicationData(encoded(&[target(3, Some(device(9)))])),
            ])
        );
        // One element by index, and the array size at index 0.
        assert_eq!(
            localize(
                &db,
                staging(),
                TARGETS,
                PropertyValue::ApplicationData(encoded(&[target(4, Some(device(7)))]))
            ),
            PropertyValue::ApplicationData(encoded(&[target(4, None)]))
        );
        assert_eq!(
            localize(&db, staging(), TARGETS, PropertyValue::Unsigned(3)),
            PropertyValue::Unsigned(3)
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
        let staged = encoded(&[target(1, Some(device(7)))]);
        let staged_value = || PropertyValue::ApplicationData(staged.clone());
        assert_eq!(localize(&db, av, TARGETS, staged_value()), staged_value());
        assert_eq!(
            localize(&db, schedule(), TARGETS, staged_value()),
            staged_value()
        );
        assert_eq!(localize(&db, staging(), LIST, value()), value());
        let mut empty = ObjectDatabase::new();
        empty
            .add(Box::new(
                ScheduleObject::new(1, "SCH-1", PropertyValue::Real(0.0)).unwrap(),
            ))
            .unwrap();
        assert_eq!(localize(&empty, schedule(), LIST, value()), value());
        assert_eq!(
            localize(&empty, staging(), TARGETS, staged_value()),
            staged_value()
        );
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
