//! Width-valid identifiers preserve identity through primitive and reference codecs.
use super::*;
use bacnet_types::constructed::{BACnetDeviceObjectReference, BACnetObjectPropertyReference};
use bacnet_types::primitives::PropertyValue;

fn boundaries() -> [(ObjectIdentifier, [u8; 4]); 3] {
    [
        (0, [0xff, 0xc0, 0x00, 0x00]),
        (
            ObjectIdentifier::MAX_ADDRESSABLE_INSTANCE,
            [0xff, 0xff, 0xff, 0xfe],
        ),
        (ObjectIdentifier::MAX_INSTANCE, [0xff, 0xff, 0xff, 0xff]),
    ]
    .map(|(instance, bytes)| {
        (
            ObjectIdentifier::new(ObjectType::from_raw(1023), instance).unwrap(),
            bytes,
        )
    })
}

#[test]
fn object_identifier_boundaries_application_and_context() {
    for (oid, wire) in boundaries() {
        let mut app = BytesMut::new();
        primitives::encode_app_object_id(&mut app, &oid);
        assert_eq!(app[0], 0xc4);
        assert_eq!(&app[1..], &wire);
        assert_eq!(
            primitives::decode_application_value(&app, 0).unwrap(),
            (PropertyValue::ObjectIdentifier(oid), 5)
        );

        let mut context = BytesMut::new();
        primitives::encode_ctx_object_id(&mut context, 2, &oid);
        assert_eq!(context[0], 0x2c);
        assert_eq!(&context[1..], &wire);
        let (tag, pos) = tags::decode_tag(&context, 0).unwrap();
        assert!(tag.is_context(2));
        assert_eq!(tag.length, 4);
        assert_eq!(ObjectIdentifier::decode(&context[pos..]).unwrap(), oid);
    }
}

#[test]
fn object_identifier_boundaries_device_object_reference() {
    for (oid, wire) in boundaries() {
        for device_identifier in [None, Some(oid)] {
            let reference = BACnetDeviceObjectReference {
                device_identifier,
                object_identifier: oid,
            };
            let mut encoded = BytesMut::new();
            encode_device_object_reference(&mut encoded, &reference);
            let mut expected = Vec::new();
            if device_identifier.is_some() {
                expected.push(0x0c);
                expected.extend_from_slice(&wire);
            }
            expected.push(0x1c);
            expected.extend_from_slice(&wire);
            assert_eq!(encoded.as_ref(), expected);
            assert_eq!(
                decode_device_object_reference(&encoded, 0).unwrap(),
                (reference, expected.len())
            );
        }
    }
}

#[test]
fn object_identifier_boundaries_object_property_reference() {
    for (oid, wire) in boundaries() {
        let reference = BACnetObjectPropertyReference::new(oid, 85);
        let mut encoded = BytesMut::new();
        encode_object_property_reference(&mut encoded, &reference);
        let mut expected = vec![0x0c];
        expected.extend_from_slice(&wire);
        expected.extend_from_slice(&[0x19, 0x55]);
        assert_eq!(encoded.as_ref(), expected);
        assert_eq!(
            decode_object_property_reference(&encoded).unwrap(),
            reference
        );
    }
}
