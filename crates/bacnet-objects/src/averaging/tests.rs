use super::*;
use bacnet_types::enums::ObjectType;

#[test]
fn averaging_create() {
    let avg = AveragingObject::new(1, "AVG-1").unwrap();
    assert_eq!(
        avg.read_property(PropertyIdentifier::OBJECT_NAME, None)
            .unwrap(),
        PropertyValue::CharacterString("AVG-1".into())
    );
    assert_eq!(
        avg.read_property(PropertyIdentifier::OBJECT_TYPE, None)
            .unwrap(),
        PropertyValue::Enumerated(ObjectType::AVERAGING.to_raw())
    );
    // The starting statistics are pinned in window_tests.rs.
    assert!(matches!(
        avg.read_property(PropertyIdentifier::AVERAGE_VALUE, None)
            .unwrap(),
        PropertyValue::Real(v) if v.is_nan()
    ));
}

#[test]
fn averaging_add_samples() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    avg.add_sample(10.0).unwrap();
    avg.add_sample(20.0).unwrap();
    avg.add_sample(30.0).unwrap();

    assert_eq!(
        avg.read_property(PropertyIdentifier::ATTEMPTED_SAMPLES, None)
            .unwrap(),
        PropertyValue::Unsigned(3)
    );
    assert_eq!(
        avg.read_property(PropertyIdentifier::VALID_SAMPLES, None)
            .unwrap(),
        PropertyValue::Unsigned(3)
    );
}

#[test]
fn averaging_min_max() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    avg.add_sample(15.0).unwrap();
    avg.add_sample(5.0).unwrap();
    avg.add_sample(25.0).unwrap();

    assert_eq!(
        avg.read_property(PropertyIdentifier::MINIMUM_VALUE, None)
            .unwrap(),
        PropertyValue::Real(5.0)
    );
    assert_eq!(
        avg.read_property(PropertyIdentifier::MAXIMUM_VALUE, None)
            .unwrap(),
        PropertyValue::Real(25.0)
    );
}

#[test]
fn averaging_average_value() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    avg.add_sample(10.0).unwrap();
    avg.add_sample(20.0).unwrap();
    avg.add_sample(30.0).unwrap();

    let val = avg
        .read_property(PropertyIdentifier::AVERAGE_VALUE, None)
        .unwrap();
    if let PropertyValue::Real(v) = val {
        assert!((v - 20.0).abs() < 0.001);
    } else {
        panic!("Expected Real");
    }
}

#[test]
fn averaging_property_list() {
    let avg = AveragingObject::new(1, "AVG-1").unwrap();
    let props = avg.property_list();
    assert!(props.contains(&PropertyIdentifier::MINIMUM_VALUE));
    assert!(props.contains(&PropertyIdentifier::MAXIMUM_VALUE));
    assert!(props.contains(&PropertyIdentifier::AVERAGE_VALUE));
    assert!(props.contains(&PropertyIdentifier::ATTEMPTED_SAMPLES));
    assert!(props.contains(&PropertyIdentifier::VALID_SAMPLES));
    assert!(props.contains(&PropertyIdentifier::OBJECT_PROPERTY_REFERENCE));
    assert!(props.contains(&PropertyIdentifier::WINDOW_INTERVAL));
    assert!(props.contains(&PropertyIdentifier::WINDOW_SAMPLES));
    // Table 12-5 defines none of these (#1064).
    for absent in [
        PropertyIdentifier::PRESENT_VALUE,
        PropertyIdentifier::STATUS_FLAGS,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyIdentifier::RELIABILITY,
        PropertyIdentifier::EVENT_STATE,
    ] {
        assert!(!props.contains(&absent), "{absent:?}");
    }
}

#[test]
fn averaging_object_property_reference_default_null() {
    let avg = AveragingObject::new(1, "AVG-1").unwrap();
    assert_eq!(
        avg.read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );
}

#[test]
fn averaging_set_object_property_reference() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 5).unwrap();
    let pv_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();
    avg.set_object_property_reference(Some(BACnetObjectPropertyReference::new(oid, pv_raw)));

    let val = avg
        .read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
        .unwrap();
    assert_eq!(
        val,
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Unsigned(pv_raw as u64),
        ])
    );
}

#[test]
fn averaging_write_object_property_reference() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap();
    let pv_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();

    avg.write_property(
        PropertyIdentifier::OBJECT_PROPERTY_REFERENCE,
        None,
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Unsigned(pv_raw as u64),
        ]),
        None,
    )
    .unwrap();

    assert_eq!(
        avg.read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
            .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Unsigned(pv_raw as u64),
        ])
    );
}

#[test]
fn averaging_write_null_clears_reference() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap();
    avg.set_object_property_reference(Some(BACnetObjectPropertyReference::new(
        oid,
        PropertyIdentifier::PRESENT_VALUE.to_raw(),
    )));

    avg.write_property(
        PropertyIdentifier::OBJECT_PROPERTY_REFERENCE,
        None,
        PropertyValue::Null,
        None,
    )
    .unwrap();

    assert_eq!(
        avg.read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );
}

#[test]
fn averaging_write_present_value_denied() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    let result = avg.write_property(
        PropertyIdentifier::PRESENT_VALUE,
        None,
        PropertyValue::Real(42.0),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn averaging_description_read_write() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    assert_eq!(
        avg.read_property(PropertyIdentifier::DESCRIPTION, None)
            .unwrap(),
        PropertyValue::CharacterString(String::new())
    );
    avg.write_property(
        PropertyIdentifier::DESCRIPTION,
        None,
        PropertyValue::CharacterString("Zone temperature averaging".into()),
        None,
    )
    .unwrap();
    assert_eq!(
        avg.read_property(PropertyIdentifier::DESCRIPTION, None)
            .unwrap(),
        PropertyValue::CharacterString("Zone temperature averaging".into())
    );
}

#[test]
fn averaging_single_sample() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    avg.add_sample(42.0).unwrap();

    assert_eq!(
        avg.read_property(PropertyIdentifier::MINIMUM_VALUE, None)
            .unwrap(),
        PropertyValue::Real(42.0)
    );
    assert_eq!(
        avg.read_property(PropertyIdentifier::MAXIMUM_VALUE, None)
            .unwrap(),
        PropertyValue::Real(42.0)
    );
    assert_eq!(
        avg.read_property(PropertyIdentifier::AVERAGE_VALUE, None)
            .unwrap(),
        PropertyValue::Real(42.0)
    );
}

// --- #182 adversary blocker: strict shared decode on the reference arm ---

#[test]
fn averaging_reference_write_accepts_exact_shapes_and_both_member_typings() {
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 7).unwrap();
    let pv_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();
    for (label, members, expect_indexed) in [
        (
            "2-member Unsigned (historical flat form)",
            vec![
                PropertyValue::ObjectIdentifier(oid),
                PropertyValue::Unsigned(pv_raw as u64),
            ],
            None,
        ),
        (
            "2-member Enumerated (Loop-family flat form)",
            vec![
                PropertyValue::ObjectIdentifier(oid),
                PropertyValue::Enumerated(pv_raw),
            ],
            None,
        ),
        (
            "3-member indexed",
            vec![
                PropertyValue::ObjectIdentifier(oid),
                PropertyValue::Unsigned(pv_raw as u64),
                PropertyValue::Unsigned(4),
            ],
            Some(4),
        ),
    ] {
        let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
        avg.write_property(
            PropertyIdentifier::OBJECT_PROPERTY_REFERENCE,
            None,
            PropertyValue::List(members),
            None,
        )
        .unwrap_or_else(|e| panic!("{label}: must be accepted: {e:?}"));
        let mut expected = vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Unsigned(pv_raw as u64),
        ];
        if let Some(idx) = expect_indexed {
            expected.push(PropertyValue::Unsigned(idx as u64));
        }
        assert_eq!(
            avg.read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
                .unwrap(),
            PropertyValue::List(expected),
            "{label}: read-back fidelity"
        );
    }
}

#[test]
fn averaging_reference_write_rejects_bad_shapes_and_preserves_state() {
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 7).unwrap();
    let pv_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();
    let baseline = PropertyValue::List(vec![
        PropertyValue::ObjectIdentifier(oid),
        PropertyValue::Unsigned(pv_raw as u64),
    ]);

    // A framed device-qualified write ([3] device-identifier): the
    // Clause 12.5 typing is BACnetDeviceObjectPropertyReference, so the
    // encoding is valid, but the remote-sample path is the standard's
    // OPTIONAL branch, unmodeled here. The object can't tell which Device
    // holds it, so any Device member is OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED
    // rather than silently local-ized (#1153; the server drops one naming
    // its own Device first).
    let mut framed_device = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_object_property_reference(
        &mut framed_device,
        &BACnetObjectPropertyReference::new(oid, pv_raw),
    );
    bacnet_encoding::primitives::encode_ctx_object_id(
        &mut framed_device,
        3,
        &ObjectIdentifier::new(ObjectType::DEVICE, 42).unwrap(),
    );

    let cases: Vec<(PropertyValue, bacnet_types::enums::ErrorCode, &str)> = vec![
        (
            PropertyValue::List(vec![
                PropertyValue::ObjectIdentifier(oid),
                PropertyValue::Unsigned(pv_raw as u64),
                PropertyValue::Unsigned(2),
                PropertyValue::Unsigned(9), // 4th member: silently dropped pre-fix
            ]),
            bacnet_types::enums::ErrorCode::INVALID_DATA_TYPE,
            "4-member list",
        ),
        (
            PropertyValue::List(vec![
                PropertyValue::ObjectIdentifier(oid),
                PropertyValue::Unsigned(pv_raw as u64),
                PropertyValue::Real(2.0), // non-Unsigned 3rd: retyped to no-index pre-fix
            ]),
            bacnet_types::enums::ErrorCode::INVALID_DATA_TYPE,
            "wrong-typed third member",
        ),
        (
            PropertyValue::List(vec![
                PropertyValue::Unsigned(1),
                PropertyValue::Unsigned(pv_raw as u64),
            ]),
            bacnet_types::enums::ErrorCode::INVALID_DATA_TYPE,
            "non-ObjectIdentifier first member",
        ),
        (
            PropertyValue::List(vec![
                PropertyValue::ObjectIdentifier(oid),
                PropertyValue::Unsigned(u64::MAX), // > 4 octets: `as u32` truncated pre-fix
            ]),
            bacnet_types::enums::ErrorCode::INVALID_DATA_TYPE,
            "oversized Unsigned property member",
        ),
        (
            PropertyValue::ApplicationData(framed_device.to_vec()),
            bacnet_types::enums::ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
            "device-qualified framed reference",
        ),
        (
            PropertyValue::ApplicationData(
                [framed_device.to_vec(), framed_device.to_vec()].concat(),
            ),
            bacnet_types::enums::ErrorCode::INVALID_DATA_ENCODING,
            "two framed references",
        ),
        (
            PropertyValue::ApplicationData(framed_device[..framed_device.len() - 1].to_vec()),
            bacnet_types::enums::ErrorCode::INVALID_DATA_ENCODING,
            "truncated device member",
        ),
    ];

    for (value, expected_code, label) in cases {
        let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
        avg.write_property(
            PropertyIdentifier::OBJECT_PROPERTY_REFERENCE,
            None,
            baseline.clone(),
            None,
        )
        .unwrap();
        let err = avg
            .write_property(
                PropertyIdentifier::OBJECT_PROPERTY_REFERENCE,
                None,
                value,
                None,
            )
            .expect_err(label);
        match err {
            Error::Protocol { class, code } => {
                assert_eq!(
                    class,
                    bacnet_types::enums::ErrorClass::PROPERTY.to_raw() as u32,
                    "{label}: wrong class"
                );
                assert_eq!(code, expected_code.to_raw() as u32, "{label}: wrong code");
            }
            other => panic!("{label}: expected Property error, got {other:?}"),
        }
        assert_eq!(
            avg.read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
                .unwrap(),
            baseline,
            "{label}: refused write must leave the stored reference untouched"
        );
    }
}

#[test]
fn averaging_reference_write_accepts_the_framed_local_form() {
    let mut avg = AveragingObject::new(1, "AVG-1").unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 7).unwrap();
    let pv_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();
    let mut framed = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_object_property_reference(
        &mut framed,
        &BACnetObjectPropertyReference::new_indexed(oid, pv_raw, 2),
    );
    avg.write_property(
        PropertyIdentifier::OBJECT_PROPERTY_REFERENCE,
        None,
        PropertyValue::ApplicationData(framed.to_vec()),
        None,
    )
    .unwrap();
    assert_eq!(
        avg.read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
            .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Unsigned(pv_raw as u64),
            PropertyValue::Unsigned(2),
        ])
    );
}
