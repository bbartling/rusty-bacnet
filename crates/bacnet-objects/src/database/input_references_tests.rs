//! A Pulse Converter's Input_Reference judged against the database (Clause
//! 12.23.9, #1341): CONFIGURATION_ERROR and the FAULT flag while it names a
//! property the converter can't count from, cleared once it names one it
//! can, re-judged as objects come and go.

use super::*;
use crate::accumulator::{AccumulatorObject, PulseConverterObject};
use crate::analog::AnalogInputObject;
use crate::value_types::IntegerValueObject;
use bacnet_types::enums::Reliability;
use bacnet_types::primitives::StatusFlags;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use PropertyIdentifier as P;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn pc1() -> ObjectIdentifier {
    oid(ObjectType::PULSE_CONVERTER, 1)
}

fn acc1() -> ObjectIdentifier {
    oid(ObjectType::ACCUMULATOR, 1)
}

/// The Clause 21 octets of a reference, as a client writes them.
fn octets(reference: &BACnetObjectPropertyReference) -> PropertyValue {
    let mut encoded = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_object_property_reference(&mut encoded, reference);
    PropertyValue::ApplicationData(encoded.to_vec())
}

fn present_value(target: ObjectIdentifier) -> BACnetObjectPropertyReference {
    BACnetObjectPropertyReference::new(target, P::PRESENT_VALUE.to_raw())
}

fn reliability(db: &ObjectDatabase, oid: ObjectIdentifier) -> Reliability {
    match db.get(&oid).unwrap().read_property(P::RELIABILITY, None) {
        Ok(PropertyValue::Enumerated(raw)) => Reliability::from_raw(raw),
        other => panic!("Reliability read {other:?}"),
    }
}

fn fault(db: &ObjectDatabase, oid: ObjectIdentifier) -> bool {
    match db.get(&oid).unwrap().read_property(P::STATUS_FLAGS, None) {
        Ok(PropertyValue::BitString { data, .. }) => {
            StatusFlags::from_bits_truncate(data[0] >> 4).contains(StatusFlags::FAULT)
        }
        other => panic!("Status_Flags read {other:?}"),
    }
}

/// A Pulse Converter named PC-1 whose Input_Reference is `reference`.
fn converter(reference: Option<BACnetObjectPropertyReference>) -> Box<PulseConverterObject> {
    let mut pc = PulseConverterObject::new(1, "PC-1", 95).unwrap();
    if let Some(reference) = reference {
        pc.set_input_reference(reference);
    }
    Box::new(pc)
}

/// Write Input_Reference as a client does, then judge it as the server
/// does when the write commits; returns whether Reliability changed.
fn write_reference(db: &mut ObjectDatabase, reference: &BACnetObjectPropertyReference) -> bool {
    db.get_mut(&pc1())
        .unwrap()
        .write_property(P::INPUT_REFERENCE, None, octets(reference), None)
        .unwrap();
    db.check_input_reference(&pc1())
}

#[test]
fn a_missing_object_faults_the_converter_until_it_is_added() {
    let mut db = ObjectDatabase::new();
    db.add(converter(Some(present_value(acc1())))).unwrap();
    assert_eq!(reliability(&db, pc1()), Reliability::CONFIGURATION_ERROR);
    assert!(fault(&db, pc1()));
    // Judged at its own add, so nothing is owed for COV yet.
    assert!(db.take_membership_work_internal().is_empty());

    // An Accumulator's Present_Value is an Unsigned: the fault clears when
    // it arrives, and the converter is owed a COV pass.
    db.add(Box::new(AccumulatorObject::new(1, "ACC-1", 95).unwrap()))
        .unwrap();
    assert_eq!(reliability(&db, pc1()), Reliability::NO_FAULT_DETECTED);
    assert!(!fault(&db, pc1()));
    assert_eq!(db.take_membership_work_internal().changed, [pc1()]);
    assert!(db.take_membership_work_internal().is_empty());

    // Deleting it brings the fault back.
    db.remove(&acc1()).unwrap();
    assert_eq!(reliability(&db, pc1()), Reliability::CONFIGURATION_ERROR);
    assert_eq!(db.take_membership_work_internal().changed, [pc1()]);
}

#[test]
fn only_unsigned_and_integer_properties_are_inputs() {
    let mut db = ObjectDatabase::new();
    db.add(converter(None)).unwrap();
    db.add(Box::new(AccumulatorObject::new(1, "ACC-1", 95).unwrap()))
        .unwrap();
    db.add(Box::new(AnalogInputObject::new(1, "AI-1", 95).unwrap()))
        .unwrap();
    db.add(Box::new(IntegerValueObject::new(1, "IV-1").unwrap()))
        .unwrap();
    assert_eq!(reliability(&db, pc1()), Reliability::NO_FAULT_DETECTED);
    let indexed = |target, property: P, index| {
        BACnetObjectPropertyReference::new_indexed(target, property.to_raw(), index)
    };
    let analog_input = oid(ObjectType::ANALOG_INPUT, 1);
    let integer_value = oid(ObjectType::INTEGER_VALUE, 1);
    for (reference, usable, what) in [
        (present_value(acc1()), true, "an Unsigned"),
        (present_value(integer_value), true, "an INTEGER"),
        (present_value(analog_input), false, "a REAL"),
        (
            BACnetObjectPropertyReference::new(acc1(), P::OBJECT_NAME.to_raw()),
            false,
            "a CharacterString",
        ),
        (
            BACnetObjectPropertyReference::new(acc1(), P::HIGH_LIMIT.to_raw()),
            false,
            "a property the object doesn't have",
        ),
        (
            indexed(acc1(), P::PRESENT_VALUE, 1),
            false,
            "an index on a property that isn't an array",
        ),
        (
            indexed(integer_value, P::PRIORITY_ARRAY, 0),
            true,
            "an array's size, an Unsigned",
        ),
        (
            indexed(integer_value, P::PRIORITY_ARRAY, 17),
            false,
            "an index past the end",
        ),
        (
            BACnetObjectPropertyReference::new(pc1(), P::COUNT.to_raw()),
            false,
            "the converter's own Count",
        ),
    ] {
        write_reference(&mut db, &reference);
        let expected = if usable {
            Reliability::NO_FAULT_DETECTED
        } else {
            Reliability::CONFIGURATION_ERROR
        };
        assert_eq!(reliability(&db, pc1()), expected, "{what}");
        assert_eq!(fault(&db, pc1()), !usable, "{what}");
    }
}

#[test]
fn an_unset_reference_is_no_fault_and_clears_one() {
    let mut db = ObjectDatabase::new();
    db.add(converter(Some(present_value(acc1())))).unwrap();
    assert_eq!(reliability(&db, pc1()), Reliability::CONFIGURATION_ERROR);
    // The object clears it itself when the reference goes, so even a write
    // the database doesn't judge leaves no stale fault.
    db.get_mut(&pc1())
        .unwrap()
        .write_property(
            P::INPUT_REFERENCE,
            None,
            octets(&crate::reference::unset_reference(ObjectType::ACCUMULATOR)),
            None,
        )
        .unwrap();
    assert_eq!(reliability(&db, pc1()), Reliability::NO_FAULT_DETECTED);
    assert!(!db.check_input_reference(&pc1()));
    assert_eq!(reliability(&db, pc1()), Reliability::NO_FAULT_DETECTED);
}

#[test]
fn the_verdict_waits_out_of_service_and_applies_on_the_return() {
    let mut db = ObjectDatabase::new();
    db.add(converter(None)).unwrap();
    let out_of_service = |db: &mut ObjectDatabase, value| {
        db.get_mut(&pc1())
            .unwrap()
            .write_property(P::OUT_OF_SERVICE, None, PropertyValue::Boolean(value), None)
            .unwrap();
    };
    out_of_service(&mut db, true);
    // Judged while out of service: Reliability stays decoupled (Clause
    // 12.23.10), so nothing changed.
    assert!(!write_reference(&mut db, &present_value(acc1())));
    assert_eq!(reliability(&db, pc1()), Reliability::NO_FAULT_DETECTED);
    out_of_service(&mut db, false);
    assert_eq!(reliability(&db, pc1()), Reliability::CONFIGURATION_ERROR);
    assert!(fault(&db, pc1()));
}

fn count(db: &ObjectDatabase) -> PropertyValue {
    db.get(&pc1())
        .unwrap()
        .read_property(P::COUNT, None)
        .unwrap()
}

/// Accumulator 1 with `value` as its Present_Value.
fn accumulator(value: u64) -> Box<AccumulatorObject> {
    let mut object = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
    object.set_present_value(value);
    Box::new(object)
}

#[test]
fn each_increase_of_the_input_is_counted_into_count() {
    let mut db = ObjectDatabase::new();
    db.add(accumulator(100)).unwrap();
    db.add(converter(Some(present_value(acc1())))).unwrap();
    // The first reading only sets the baseline.
    assert!(db.count_pulse_inputs().is_empty());
    assert_eq!(count(&db), PropertyValue::Unsigned(0));
    db.add(accumulator(107)).unwrap();
    assert_eq!(db.count_pulse_inputs(), [pc1()]);
    assert_eq!(count(&db), PropertyValue::Unsigned(7));
    // No increase, nothing counted.
    assert!(db.count_pulse_inputs().is_empty());
    // A reading below the last one sets the baseline again without counting.
    db.add(accumulator(3)).unwrap();
    assert!(db.count_pulse_inputs().is_empty());
    db.add(accumulator(5)).unwrap();
    assert_eq!(db.count_pulse_inputs(), [pc1()]);
    assert_eq!(count(&db), PropertyValue::Unsigned(9));
    // Nothing to read drops the baseline, so the object's return counts
    // from its first reading again.
    db.remove(&acc1()).unwrap();
    assert!(db.count_pulse_inputs().is_empty());
    db.add(accumulator(50)).unwrap();
    assert!(db.count_pulse_inputs().is_empty());
    db.add(accumulator(51)).unwrap();
    assert_eq!(db.count_pulse_inputs(), [pc1()]);
    assert_eq!(count(&db), PropertyValue::Unsigned(10));
    // A new reference starts its own baseline.
    db.add(Box::new(IntegerValueObject::new(1, "IV-1").unwrap()))
        .unwrap();
    write_reference(&mut db, &present_value(oid(ObjectType::INTEGER_VALUE, 1)));
    db.add(accumulator(60)).unwrap();
    assert!(db.count_pulse_inputs().is_empty());
    assert_eq!(count(&db), PropertyValue::Unsigned(10));
}

#[test]
fn a_changed_converter_wakes_the_server_once_per_queued_change() {
    let mut db = ObjectDatabase::new();
    let wakes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&wakes);
    db.set_membership_waker_internal(Some(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    })));
    db.add(converter(Some(present_value(acc1())))).unwrap();
    // Unrelated adds queue nothing and wake nobody.
    db.add(Box::new(AnalogInputObject::new(1, "AI-1", 95).unwrap()))
        .unwrap();
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    db.add(Box::new(AccumulatorObject::new(1, "ACC-1", 95).unwrap()))
        .unwrap();
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    // Replacing the target judges again; a verdict that stands changes
    // nothing, so it queues nothing.
    db.add(Box::new(AccumulatorObject::new(1, "ACC-1", 95).unwrap()))
        .unwrap();
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(db.take_membership_work_internal().changed, [pc1()]);
}
