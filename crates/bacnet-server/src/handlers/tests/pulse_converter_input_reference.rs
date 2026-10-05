//! A Pulse Converter judges the Input_Reference a client writes against
//! the database as the write commits (Clause 12.23.9, #1341): Reliability
//! reads CONFIGURATION_ERROR, and Status_Flags FAULT, while the reference
//! names a property the converter can't count from, and clears once it
//! names one it can. Over WriteProperty, WritePropertyMultiple and a
//! CreateObject's initial values alike.

use super::*;
use bacnet_objects::accumulator::{AccumulatorObject, PulseConverterObject};
use bacnet_objects::analog::AnalogInputObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_types::enums::Reliability;

const INPUT: PropertyIdentifier = PropertyIdentifier::INPUT_REFERENCE;
/// [0] accumulator 1, [1] present-value: an Unsigned.
const ACC_1_PV: [u8; 7] = [0x0C, 0x05, 0xC0, 0x00, 0x01, 0x19, 0x55];
/// [0] analog-input 1, [1] present-value: a REAL.
const AI_1_PV: [u8; 7] = [0x0C, 0x00, 0x00, 0x00, 0x01, 0x19, 0x55];
/// [0] accumulator 2, [1] present-value: no such object.
const ACC_2_PV: [u8; 7] = [0x0C, 0x05, 0xC0, 0x00, 0x02, 0x19, 0x55];
/// The unset form: [0] accumulator 4194303, [1] present-value.
const UNSET: [u8; 7] = [0x0C, 0x05, 0xFF, 0xFF, 0xFF, 0x19, 0x55];
const FAULT: u8 = 0x40;

fn pc1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::PULSE_CONVERTER, 1).unwrap()
}

/// PC-1 without a reference, Accumulator 1 and Analog Input 1.
fn database() -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    db.add(Box::new(PulseConverterObject::new(1, "PC-1", 95).unwrap()))
        .unwrap();
    db.add(Box::new(AccumulatorObject::new(1, "ACC-1", 95).unwrap()))
        .unwrap();
    db.add(Box::new(AnalogInputObject::new(1, "AI-1", 95).unwrap()))
        .unwrap();
    db
}

fn write(db: &mut ObjectDatabase, octets: &[u8]) {
    let request = WritePropertyRequest {
        object_identifier: pc1(),
        property_identifier: INPUT,
        property_array_index: None,
        property_value: octets.to_vec(),
        priority: None,
    };
    let mut bytes = BytesMut::new();
    request.encode(&mut bytes).unwrap();
    handle_write_property(db, &bytes).unwrap();
}

fn write_multiple(db: &mut ObjectDatabase, octets: &[u8]) {
    let request = WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: pc1(),
            list_of_properties: vec![BACnetPropertyValue {
                property_identifier: INPUT,
                property_array_index: None,
                value: octets.to_vec(),
                priority: None,
            }],
        }],
    };
    let mut bytes = BytesMut::new();
    request.encode(&mut bytes).unwrap();
    handle_write_property_multiple(db, &bytes).unwrap();
}

/// Reliability and the Status_Flags bits, as a ReadProperty of each serves
/// them.
fn state(db: &ObjectDatabase) -> (Reliability, u8) {
    let read = |property: PropertyIdentifier| {
        let request = ReadPropertyRequest {
            object_identifier: pc1(),
            property_identifier: property,
            property_array_index: None,
        };
        let mut bytes = BytesMut::new();
        request.encode(&mut bytes);
        let mut ack = BytesMut::new();
        handle_read_property(db, &bytes, &mut ack).unwrap();
        ReadPropertyACK::decode(&ack).unwrap().property_value
    };
    let reliability = read(PropertyIdentifier::RELIABILITY);
    assert_eq!(reliability[0], 0x91, "an Enumerated");
    let flags = read(PropertyIdentifier::STATUS_FLAGS);
    assert_eq!(&flags[..2], &[0x82, 0x04], "four-bit Status_Flags");
    (Reliability::from_raw(u32::from(reliability[1])), flags[2])
}

#[test]
fn a_written_reference_is_judged_as_the_write_commits() {
    let mut db = database();
    assert_eq!(state(&db), (Reliability::NO_FAULT_DETECTED, 0));
    for (octets, reliability, flags, what) in [
        (&AI_1_PV, Reliability::CONFIGURATION_ERROR, FAULT, "a REAL"),
        (&ACC_1_PV, Reliability::NO_FAULT_DETECTED, 0, "an Unsigned"),
        (
            &ACC_2_PV,
            Reliability::CONFIGURATION_ERROR,
            FAULT,
            "a missing object",
        ),
        (&UNSET, Reliability::NO_FAULT_DETECTED, 0, "no reference"),
    ] {
        write(&mut db, octets);
        assert_eq!(state(&db), (reliability, flags), "WriteProperty of {what}");
        write_multiple(&mut db, &ACC_1_PV);
        write_multiple(&mut db, octets);
        assert_eq!(state(&db), (reliability, flags), "WPM of {what}");
    }
}

#[test]
fn a_null_leaves_the_reference_and_its_verdict_as_they_are() {
    let mut db = database();
    write(&mut db, &AI_1_PV);
    write(&mut db, &[0x00]);
    assert_eq!(state(&db), (Reliability::CONFIGURATION_ERROR, FAULT));
}

#[test]
fn deleting_and_recreating_the_named_object_moves_the_fault() {
    let mut db = database();
    write(&mut db, &ACC_1_PV);
    assert_eq!(state(&db), (Reliability::NO_FAULT_DETECTED, 0));
    let accumulator = ObjectIdentifier::new(ObjectType::ACCUMULATOR, 1).unwrap();
    db.remove(&accumulator).unwrap();
    assert_eq!(state(&db), (Reliability::CONFIGURATION_ERROR, FAULT));
    assert_eq!(db.take_membership_work_internal().changed, [pc1()]);
    db.add(Box::new(AccumulatorObject::new(1, "ACC-1", 95).unwrap()))
        .unwrap();
    assert_eq!(state(&db), (Reliability::NO_FAULT_DETECTED, 0));
    assert_eq!(db.take_membership_work_internal().changed, [pc1()]);
}
