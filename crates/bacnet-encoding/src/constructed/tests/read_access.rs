//! Clause 21 BACnetPropertyReference and ReadAccessSpecification vectors
//! (#1134). The octets are written out from the production tags, not
//! produced by this codec.

use crate::constructed::{
    decode_property_reference, decode_read_access_specification, encode_property_reference,
    encode_read_access_specification,
};
use crate::primitives;
use bacnet_types::constructed::{PropertyReference, ReadAccessSpecification};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;

fn reference(property: PropertyIdentifier, index: Option<u32>) -> PropertyReference {
    PropertyReference {
        property_identifier: property,
        property_array_index: index,
    }
}

#[test]
fn property_references_encode_and_decode_with_and_without_an_index() {
    for (value, octets) in [
        (
            reference(PropertyIdentifier::PRESENT_VALUE, None),
            &[0x09, 85][..],
        ),
        (
            reference(PropertyIdentifier::PRIORITY_ARRAY, Some(8)),
            &[0x09, 87, 0x19, 8][..],
        ),
    ] {
        let mut buf = BytesMut::new();
        encode_property_reference(&mut buf, &value);
        assert_eq!(&buf[..], octets);
        assert_eq!(
            decode_property_reference(octets, 0).unwrap(),
            (value, octets.len())
        );
    }
}

#[test]
fn malformed_property_references_are_refused() {
    let mut indexed = BytesMut::new();
    encode_property_reference(
        &mut indexed,
        &reference(PropertyIdentifier::PRESENT_VALUE, Some(8)),
    );
    for bad in [&[][..], &indexed[..1], &[0xFF, 0xFF, 0xFF][..]] {
        assert!(decode_property_reference(bad, 0).is_err(), "{bad:02X?}");
    }
    // Both members must fit u32.
    for overflow in [u64::from(u32::MAX) + 1, u64::MAX] {
        let mut property = BytesMut::new();
        primitives::encode_ctx_unsigned(&mut property, 0, overflow);
        assert!(decode_property_reference(&property, 0).is_err());
        let mut index = BytesMut::new();
        primitives::encode_ctx_unsigned(&mut index, 0, 1);
        primitives::encode_ctx_unsigned(&mut index, 1, overflow);
        assert!(decode_property_reference(&index, 0).is_err());
    }
}

#[test]
fn read_access_specifications_decode_one_element_at_an_offset() {
    // AV-2 Present_Value, then Priority_Array[16], as one element of a
    // Group's List_Of_Group_Members.
    let spec = ReadAccessSpecification {
        object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 2).unwrap(),
        list_of_property_references: vec![
            reference(PropertyIdentifier::PRESENT_VALUE, None),
            reference(PropertyIdentifier::PRIORITY_ARRAY, Some(16)),
        ],
    };
    let octets = [
        0x0C, 0, 0x80, 0, 2, 0x1E, 0x09, 85, 0x09, 87, 0x19, 16, 0x1F,
    ];
    let mut buf = BytesMut::from(&b"xy"[..]);
    encode_read_access_specification(&mut buf, &spec);
    assert_eq!(&buf[2..], &octets);
    buf.extend_from_slice(&[0xAA]);
    assert_eq!(
        decode_read_access_specification(&buf, 2).unwrap(),
        (spec, 2 + octets.len())
    );
    // No reference list encodes as the bare [1] pair.
    let empty = ReadAccessSpecification {
        object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 2).unwrap(),
        list_of_property_references: vec![],
    };
    let mut encoded = BytesMut::new();
    encode_read_access_specification(&mut encoded, &empty);
    assert_eq!(&encoded[..], &[0x0C, 0, 0x80, 0, 2, 0x1E, 0x1F]);
    assert_eq!(
        decode_read_access_specification(&encoded, 0).unwrap(),
        (empty, encoded.len())
    );
}

#[test]
fn malformed_read_access_specifications_are_refused() {
    let octets = [
        0x0C, 0, 0x80, 0, 2, 0x1E, 0x09, 85, 0x09, 87, 0x19, 16, 0x1F,
    ];
    // Truncated anywhere, including just before the closing tag.
    for end in [0, 4, 5, 6, 9, octets.len() - 1] {
        assert!(decode_read_access_specification(&octets[..end], 0).is_err());
    }
    // The object under the wrong tag, and no opening [1].
    assert!(decode_read_access_specification(&[0x1C, 0, 0x80, 0, 2, 0x1E, 0x1F], 0).is_err());
    assert!(decode_read_access_specification(&[0x0C, 0, 0x80, 0, 2, 0x2E, 0x2F], 0).is_err());
}
