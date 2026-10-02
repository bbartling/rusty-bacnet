//! Clause 21 BACnetPropertyAccessResult vectors (#1107). The octets are
//! written out from the production tags, not produced by this codec.

use crate::constructed::{
    decode_device_object_property_reference, decode_property_access_result,
    encode_device_object_property_reference, encode_property_access_result,
};
use bacnet_types::constructed::{
    AccessResult, BACnetDeviceObjectPropertyReference, BACnetPropertyAccessResult,
};
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::BytesMut;

fn oid(kind: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(kind, instance).unwrap()
}

/// AI-1 Present_Value (local) and AV-3 Priority_Array[8] in device 1234.
fn local() -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference::new_local(oid(ObjectType::ANALOG_INPUT, 1), 85)
}
const LOCAL: &[u8] = &[0x0C, 0x00, 0x00, 0x00, 0x01, 0x19, 0x55];

fn remote() -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference::new_remote(
        oid(ObjectType::ANALOG_VALUE, 3),
        87,
        oid(ObjectType::DEVICE, 1234),
    )
    .with_index(8)
}
const REMOTE: &[u8] = &[
    0x0C, 0x00, 0x80, 0x00, 0x03, 0x19, 0x57, 0x29, 0x08, 0x3C, 0x02, 0x00, 0x04, 0xD2,
];

fn vectors() -> Vec<(BACnetPropertyAccessResult, Vec<u8>)> {
    let element = |reference, access_result| BACnetPropertyAccessResult {
        reference,
        access_result,
    };
    vec![
        (
            element(local(), AccessResult::Value(PropertyValue::Real(21.5))),
            [LOCAL, &[0x4E, 0x44, 0x41, 0xAC, 0x00, 0x00, 0x4F]].concat(),
        ),
        (
            element(
                remote(),
                AccessResult::Error {
                    class: ErrorClass::COMMUNICATION,
                    code: ErrorCode::TIMEOUT,
                },
            ),
            [REMOTE, &[0x5E, 0x91, 0x07, 0x91, 0x1E, 0x5F]].concat(),
        ),
        (
            element(local(), AccessResult::NOT_INITIALIZED),
            [LOCAL, &[0x5E, 0x91, 0x02, 0x91, 0x48, 0x5F]].concat(),
        ),
        // A whole array read as the value: several elements, or none.
        (
            element(
                remote(),
                AccessResult::Value(PropertyValue::List(vec![
                    PropertyValue::Null,
                    PropertyValue::Unsigned(7),
                ])),
            ),
            [REMOTE, &[0x4E, 0x00, 0x21, 0x07, 0x4F]].concat(),
        ),
        (
            element(local(), AccessResult::Value(PropertyValue::List(vec![]))),
            [LOCAL, &[0x4E, 0x4F]].concat(),
        ),
        // A constructed value keeps its octets.
        (
            element(
                local(),
                AccessResult::Value(PropertyValue::ApplicationData(vec![0x0E, 0x21, 0x01, 0x0F])),
            ),
            [LOCAL, &[0x4E, 0x0E, 0x21, 0x01, 0x0F, 0x4F]].concat(),
        ),
    ]
}

#[test]
fn property_access_results_encode_and_decode_to_the_production_octets() {
    for (element, octets) in vectors() {
        let mut encoded = BytesMut::new();
        encode_property_access_result(&mut encoded, &element).unwrap();
        assert_eq!(&encoded[..], &octets[..], "{element:?}");
        assert_eq!(
            decode_property_access_result(&octets, 0).unwrap(),
            (element, octets.len())
        );
    }
}

#[test]
fn an_array_of_access_results_decodes_one_element_at_a_time() {
    let vectors = vectors();
    let array: Vec<u8> = vectors.iter().flat_map(|(_, o)| o.clone()).collect();
    let mut offset = 0;
    for (element, _) in &vectors {
        let (decoded, next) = decode_property_access_result(&array, offset).unwrap();
        assert_eq!(&decoded, element);
        offset = next;
    }
    assert_eq!(offset, array.len());
}

#[test]
fn malformed_access_results_are_refused() {
    let cases: [(&str, Vec<u8>); 7] = [
        ("no result", LOCAL.to_vec()),
        ("primitive [4]", [LOCAL, &[0x49, 0x01]].concat()),
        ("unclosed value", [LOCAL, &[0x4E, 0x21, 0x07]].concat()),
        (
            "unclosed error",
            [LOCAL, &[0x5E, 0x91, 0x02, 0x91, 0x48]].concat(),
        ),
        (
            "error code missing",
            [LOCAL, &[0x5E, 0x91, 0x02, 0x5F]].concat(),
        ),
        (
            "unsigned class",
            [LOCAL, &[0x5E, 0x21, 0x02, 0x91, 0x48, 0x5F]].concat(),
        ),
        (
            "class past u16",
            [LOCAL, &[0x5E, 0x93, 0x01, 0x00, 0x00, 0x91, 0x48, 0x5F]].concat(),
        ),
    ];
    for (what, octets) in cases {
        assert!(decode_property_access_result(&octets, 0).is_err(), "{what}");
    }
}

#[test]
fn device_object_property_references_encode_bare() {
    for (reference, octets) in [(local(), LOCAL), (remote(), REMOTE)] {
        let mut encoded = BytesMut::new();
        encode_device_object_property_reference(&mut encoded, &reference);
        assert_eq!(&encoded[..], octets);
        assert_eq!(
            decode_device_object_property_reference(octets, 0).unwrap(),
            (reference, octets.len())
        );
    }
}
