//! Access Door's BACnetDoorValue properties and Access Credential's
//! BACnetBinaryPV Credential_Status (#979).
//!
//! Table 12-30 types the door's Present_Value, Priority_Array slots and
//! Relinquish_Default as BACnetDoorValue, a closed set of four. Table 12-40
//! types Credential_Status as BACnetBinaryPV, a closed set of two, and has
//! no Present_Value row. A value outside the set is refused with
//! VALUE_OUT_OF_RANGE and nothing is stored.

use super::*;
use bacnet_types::enums::{ErrorClass, ErrorCode};

const P: PropertyIdentifier = PropertyIdentifier::PRESENT_VALUE;
const PA: PropertyIdentifier = PropertyIdentifier::PRIORITY_ARRAY;
const RD: PropertyIdentifier = PropertyIdentifier::RELINQUISH_DEFAULT;
const CS: PropertyIdentifier = PropertyIdentifier::CREDENTIAL_STATUS;

/// Values outside both closed sets: the first past BACnetDoorValue, an
/// unnamed small value, a 16-bit vendor-range value and the largest
/// encodable Enumerated.
const OUTSIDE_DOOR_VALUE: [u32; 4] = [4, 200, 1024, u32::MAX];

fn assert_property_error(result: Result<(), Error>, expected: ErrorCode) {
    match result {
        Err(Error::Protocol { class, code }) => {
            assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
            assert_eq!(code, expected.to_raw() as u32, "expected {expected:?}");
        }
        other => panic!("expected PROPERTY / {expected:?}, got {other:?}"),
    }
}

fn read(object: &dyn BACnetObject, property: PropertyIdentifier) -> PropertyValue {
    object.read_property(property, None).unwrap()
}

fn read_slot(object: &dyn BACnetObject, slot: u32) -> PropertyValue {
    object.read_property(PA, Some(slot)).unwrap()
}

#[test]
fn access_door_present_value_commands_each_door_value() {
    let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
    for &(name, value) in DoorValue::ALL_NAMED {
        let raw = PropertyValue::Enumerated(value.to_raw());
        door.write_property(P, None, raw.clone(), Some(8))
            .unwrap_or_else(|e| panic!("{name} must be accepted: {e:?}"));
        assert_eq!(read(&door, P), raw, "{name}");
        assert_eq!(read_slot(&door, 8), raw, "{name}");
    }
    // The whole array carries the typed slot as an Enumerated, and an
    // unset slot as NULL.
    let PropertyValue::List(slots) = read(&door, PA) else {
        panic!("Priority_Array must read as a list");
    };
    assert_eq!(slots.len(), 16);
    assert_eq!(
        slots[7],
        PropertyValue::Enumerated(DoorValue::EXTENDED_PULSE_UNLOCK.to_raw())
    );
    assert!(slots
        .iter()
        .enumerate()
        .all(|(i, slot)| i == 7 || *slot == PropertyValue::Null));
    assert_eq!(read_slot(&door, 0), PropertyValue::Unsigned(16));

    // A higher priority outranks slot 8; relinquishing both falls back to
    // Relinquish_Default.
    door.write_property(
        P,
        None,
        PropertyValue::Enumerated(DoorValue::UNLOCK.to_raw()),
        Some(1),
    )
    .unwrap();
    assert_eq!(read(&door, P), PropertyValue::Enumerated(1));
    for slot in [1, 8] {
        door.write_property(P, None, PropertyValue::Null, Some(slot))
            .unwrap();
    }
    assert_eq!(read(&door, P), PropertyValue::Enumerated(0));
    // A write without a priority commands slot 16.
    door.write_property(P, None, PropertyValue::Enumerated(2), None)
        .unwrap();
    assert_eq!(read_slot(&door, 16), PropertyValue::Enumerated(2));
    assert_eq!(read(&door, P), PropertyValue::Enumerated(2));
}

#[test]
fn access_door_present_value_refuses_values_outside_door_value_atomically() {
    let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
    door.write_property(P, None, PropertyValue::Enumerated(1), Some(8))
        .unwrap();
    let before = [read(&door, P), read(&door, PA), read(&door, RD)];
    for raw in OUTSIDE_DOOR_VALUE {
        // Both into the active slot and into an empty, higher one.
        for priority in [Some(8), Some(1), None] {
            assert_property_error(
                door.write_property(P, None, PropertyValue::Enumerated(raw), priority),
                ErrorCode::VALUE_OUT_OF_RANGE,
            );
        }
    }
    for value in [
        PropertyValue::Unsigned(1),
        PropertyValue::Real(1.0),
        PropertyValue::Boolean(true),
    ] {
        assert_property_error(
            door.write_property(P, None, value, Some(8)),
            ErrorCode::INVALID_DATA_TYPE,
        );
    }
    assert_eq!(
        [read(&door, P), read(&door, PA), read(&door, RD)],
        before,
        "a refused command must leave Present_Value, Priority_Array and Relinquish_Default as they were"
    );
}

#[test]
fn access_door_set_relinquish_default_takes_a_door_value() {
    let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
    assert_eq!(read(&door, RD), PropertyValue::Enumerated(0));
    for &(name, value) in DoorValue::ALL_NAMED {
        door.set_relinquish_default(value)
            .unwrap_or_else(|e| panic!("{name} must be accepted: {e:?}"));
        assert_eq!(read(&door, RD), PropertyValue::Enumerated(value.to_raw()));
        assert_eq!(read(&door, P), PropertyValue::Enumerated(value.to_raw()));
    }
    // `from_raw` can build a DoorValue outside the production; the setter
    // refuses it and keeps the stored default.
    for raw in OUTSIDE_DOOR_VALUE {
        assert_property_error(
            door.set_relinquish_default(DoorValue::from_raw(raw)),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_eq!(read(&door, RD), PropertyValue::Enumerated(3));
        assert_eq!(read(&door, P), PropertyValue::Enumerated(3));
    }
}

#[test]
fn access_credential_status_accepts_inactive_and_active() {
    let mut credential = AccessCredentialObject::new(1, "CRED-1").unwrap();
    assert_eq!(
        read(&credential, CS),
        PropertyValue::Enumerated(BinaryPV::INACTIVE.to_raw())
    );
    for value in [BinaryPV::ACTIVE, BinaryPV::INACTIVE, BinaryPV::ACTIVE] {
        let raw = PropertyValue::Enumerated(value.to_raw());
        credential
            .write_property(CS, None, raw.clone(), None)
            .unwrap();
        assert_eq!(read(&credential, CS), raw);
    }
}

#[test]
fn access_credential_status_refuses_values_outside_binary_pv_atomically() {
    let mut credential = AccessCredentialObject::new(1, "CRED-1").unwrap();
    credential
        .write_property(CS, None, PropertyValue::Enumerated(1), None)
        .unwrap();
    for raw in [2, 3].into_iter().chain(OUTSIDE_DOOR_VALUE) {
        assert_property_error(
            credential.write_property(CS, None, PropertyValue::Enumerated(raw), None),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_eq!(read(&credential, CS), PropertyValue::Enumerated(1));
    }
    for value in [
        PropertyValue::Unsigned(0),
        PropertyValue::Boolean(false),
        PropertyValue::Null,
    ] {
        assert_property_error(
            credential.write_property(CS, None, value, None),
            ErrorCode::INVALID_DATA_TYPE,
        );
        assert_eq!(read(&credential, CS), PropertyValue::Enumerated(1));
    }
}

#[test]
fn access_credential_has_no_present_value() {
    let mut credential = AccessCredentialObject::new(1, "CRED-1").unwrap();
    assert!(!credential.property_list().contains(&P));
    assert!(!credential
        .property_metadata()
        .iter()
        .any(|row| row.property_identifier == P));
    assert!(!credential.is_writable_property(P));
    assert_property_error(
        credential.read_property(P, None).map(|_| ()),
        ErrorCode::UNKNOWN_PROPERTY,
    );
    for value in [
        PropertyValue::Enumerated(0),
        PropertyValue::Enumerated(1),
        PropertyValue::Null,
    ] {
        assert_property_error(
            credential.write_property(P, None, value, None),
            ErrorCode::UNKNOWN_PROPERTY,
        );
    }
    // A Present_Value write never reaches Credential_Status.
    assert_eq!(read(&credential, CS), PropertyValue::Enumerated(0));
}
