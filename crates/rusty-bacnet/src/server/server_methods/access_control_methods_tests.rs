use super::*;
use bacnet_objects::traits::BACnetObject;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn py(object_type: ObjectType, instance: u32) -> PyObjectIdentifier {
    PyObjectIdentifier::from_rust(oid(object_type, instance))
}

fn size(object: &dyn BACnetObject, property: PropertyIdentifier) -> PropertyValue {
    object.read_property(property, Some(0)).unwrap()
}

fn is_value_out_of_range(error: &Error) -> bool {
    matches!(error, Error::Protocol { class, code }
        if *class == ErrorClass::PROPERTY.to_raw() as u32
            && *code == ErrorCode::VALUE_OUT_OF_RANGE.to_raw() as u32)
}

#[test]
fn python_door_members_and_access_doors_reach_the_arrays() {
    let local = || PyDeviceObjectReference::Local(py(ObjectType::BINARY_INPUT, 3));
    let remote = || {
        PyDeviceObjectReference::Remote(py(ObjectType::DEVICE, 99), py(ObjectType::ACCESS_DOOR, 4))
    };
    let door = access_door(1, "DOOR-1", Some(vec![local(), remote()])).unwrap();
    let mut expected = AccessDoorObject::new(1, "DOOR-1").unwrap();
    expected.set_door_members([
        BACnetDeviceObjectReference::from(oid(ObjectType::BINARY_INPUT, 3)),
        BACnetDeviceObjectReference {
            device_identifier: Some(oid(ObjectType::DEVICE, 99)),
            object_identifier: oid(ObjectType::ACCESS_DOOR, 4),
        },
    ]);
    for index in [Some(0), None] {
        assert_eq!(
            door.read_property(PropertyIdentifier::DOOR_MEMBERS, index)
                .unwrap(),
            expected
                .read_property(PropertyIdentifier::DOOR_MEMBERS, index)
                .unwrap()
        );
    }

    let point = access_point(1, "AP-1", Some(vec![remote()])).unwrap();
    assert_eq!(
        size(&point, PropertyIdentifier::ACCESS_DOORS),
        PropertyValue::Unsigned(1)
    );
    // Access_Doors names Access Doors only.
    let refused = access_point(2, "AP-2", Some(vec![local()])).err().unwrap();
    assert!(is_value_out_of_range(&refused), "{refused:?}");

    // Omitted arguments keep the empty arrays.
    let door = access_door(3, "DOOR-3", None).unwrap();
    assert_eq!(
        size(&door, PropertyIdentifier::DOOR_MEMBERS),
        PropertyValue::Unsigned(0)
    );
    let point = access_point(3, "AP-3", None).unwrap();
    assert_eq!(
        size(&point, PropertyIdentifier::ACCESS_DOORS),
        PropertyValue::Unsigned(0)
    );
}

#[test]
fn python_supported_formats_reach_both_arrays() {
    // Wiegand 26 (8) in class 0, and vendor 260's format 7 (CUSTOM, 2) in
    // class 3.
    let reader = credential_data_input(
        1,
        "CDI-1",
        Some(vec![
            (PyFactorFormat::Standard(8), 0),
            (PyFactorFormat::Vendor(2, 260, 7), 3),
        ]),
    )
    .unwrap();
    // format type [0] CUSTOM, vendor id [1] 260, vendor format [2] 7.
    assert_eq!(
        reader
            .read_property(PropertyIdentifier::SUPPORTED_FORMATS, Some(2))
            .unwrap(),
        PropertyValue::ApplicationData(vec![0x09, 0x02, 0x1A, 0x01, 0x04, 0x29, 0x07])
    );
    assert_eq!(
        reader
            .read_property(PropertyIdentifier::SUPPORTED_FORMAT_CLASSES, None)
            .unwrap(),
        PropertyValue::List(vec![PropertyValue::Unsigned(0), PropertyValue::Unsigned(3)])
    );

    for formats in [
        // A CUSTOM format without its vendor members, a vendor member on
        // another format, a vendor member past Unsigned16, a type past the
        // closed production.
        vec![(PyFactorFormat::Standard(2), 0)],
        vec![(PyFactorFormat::Vendor(8, 260, 7), 0)],
        vec![(PyFactorFormat::Vendor(2, 65_536, 7), 0)],
        vec![(PyFactorFormat::Standard(25), 0)],
    ] {
        let refused = credential_data_input(2, "CDI-2", Some(formats))
            .err()
            .unwrap();
        assert!(is_value_out_of_range(&refused), "{refused:?}");
    }
    let bare = credential_data_input(3, "CDI-3", None).unwrap();
    assert_eq!(
        size(&bare, PropertyIdentifier::SUPPORTED_FORMATS),
        PropertyValue::Unsigned(0)
    );
}
