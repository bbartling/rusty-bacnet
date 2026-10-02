use super::*;

#[test]
fn loop_read_defaults() {
    let lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    assert_eq!(
        lo.read_property(PropertyIdentifier::PRESENT_VALUE, None)
            .unwrap(),
        PropertyValue::Real(0.0)
    );
    assert_eq!(
        lo.read_property(PropertyIdentifier::SETPOINT, None)
            .unwrap(),
        PropertyValue::Real(0.0)
    );
    assert_eq!(
        lo.read_property(PropertyIdentifier::PROPORTIONAL_CONSTANT, None)
            .unwrap(),
        PropertyValue::Real(1.0)
    );
}

#[test]
fn loop_write_pid_constants() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    lo.write_property(
        PropertyIdentifier::SETPOINT,
        None,
        PropertyValue::Real(72.0),
        None,
    )
    .unwrap();
    lo.write_property(
        PropertyIdentifier::PROPORTIONAL_CONSTANT,
        None,
        PropertyValue::Real(2.5),
        None,
    )
    .unwrap();
    lo.write_property(
        PropertyIdentifier::INTEGRAL_CONSTANT,
        None,
        PropertyValue::Real(0.1),
        None,
    )
    .unwrap();
    lo.write_property(
        PropertyIdentifier::DERIVATIVE_CONSTANT,
        None,
        PropertyValue::Real(0.05),
        None,
    )
    .unwrap();

    assert_eq!(
        lo.read_property(PropertyIdentifier::SETPOINT, None)
            .unwrap(),
        PropertyValue::Real(72.0)
    );
    assert_eq!(
        lo.read_property(PropertyIdentifier::PROPORTIONAL_CONSTANT, None)
            .unwrap(),
        PropertyValue::Real(2.5)
    );
    assert_eq!(
        lo.read_property(PropertyIdentifier::INTEGRAL_CONSTANT, None)
            .unwrap(),
        PropertyValue::Real(0.1)
    );
    assert_eq!(
        lo.read_property(PropertyIdentifier::DERIVATIVE_CONSTANT, None)
            .unwrap(),
        PropertyValue::Real(0.05)
    );
}

#[test]
fn loop_set_present_value() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    lo.set_present_value(55.0);
    assert_eq!(
        lo.read_property(PropertyIdentifier::PRESENT_VALUE, None)
            .unwrap(),
        PropertyValue::Real(55.0)
    );
}

#[test]
fn loop_read_object_type() {
    let lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let val = lo
        .read_property(PropertyIdentifier::OBJECT_TYPE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Enumerated(ObjectType::LOOP.to_raw()));
}

#[test]
fn loop_write_wrong_type_rejected() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let result = lo.write_property(
        PropertyIdentifier::SETPOINT,
        None,
        PropertyValue::Unsigned(72),
        None,
    );
    assert!(result.is_err());
}

// --- Property reference tests ---

#[test]
fn loop_references_default_to_null() {
    let lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    assert_eq!(
        lo.read_property(PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );
    assert_eq!(
        lo.read_property(PropertyIdentifier::MANIPULATED_VARIABLE_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );
    assert_eq!(
        lo.read_property(PropertyIdentifier::SETPOINT_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );
}

#[test]
fn loop_set_references_read_back() {
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 5).unwrap();
    let prop_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();
    let expect = PropertyValue::List(vec![
        PropertyValue::ObjectIdentifier(oid),
        PropertyValue::Enumerated(prop_raw),
    ]);
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    lo.set_controlled_variable_reference(BACnetObjectPropertyReference::new(oid, prop_raw));
    lo.set_manipulated_variable_reference(BACnetObjectPropertyReference::new(oid, prop_raw));
    lo.set_setpoint_reference(BACnetObjectPropertyReference::new(oid, prop_raw));
    for property in [
        PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE,
        PropertyIdentifier::MANIPULATED_VARIABLE_REFERENCE,
        PropertyIdentifier::SETPOINT_REFERENCE,
    ] {
        assert_eq!(lo.read_property(property, None).unwrap(), expect);
    }
}

#[test]
fn loop_references_in_property_list() {
    let lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let list = lo.property_list();
    assert!(list.contains(&PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE));
    assert!(list.contains(&PropertyIdentifier::MANIPULATED_VARIABLE_REFERENCE));
    assert!(list.contains(&PropertyIdentifier::SETPOINT_REFERENCE));
}

#[test]
fn loop_write_reference_via_write_property() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 7).unwrap();
    let prop_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();

    lo.write_property(
        PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE,
        None,
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Enumerated(prop_raw),
        ]),
        None,
    )
    .unwrap();

    assert_eq!(
        lo.read_property(PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE, None)
            .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Enumerated(prop_raw),
        ])
    );
}

#[test]
fn loop_write_null_clears_reference() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap();
    lo.set_controlled_variable_reference(BACnetObjectPropertyReference::new(
        oid,
        PropertyIdentifier::PRESENT_VALUE.to_raw(),
    ));

    // Verify it is set
    assert_ne!(
        lo.read_property(PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );

    // Write Null to clear
    lo.write_property(
        PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE,
        None,
        PropertyValue::Null,
        None,
    )
    .unwrap();

    assert_eq!(
        lo.read_property(PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );
}

#[test]
fn loop_write_reference_wrong_type_rejected() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let result = lo.write_property(
        PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE,
        None,
        PropertyValue::Unsigned(42),
        None,
    );
    assert!(result.is_err());
}

// --- #182: framed (context-tagged) reference writes ---

fn framed_reference(r: &BACnetObjectPropertyReference) -> PropertyValue {
    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_object_property_reference(&mut buf, r);
    PropertyValue::ApplicationData(buf.to_vec())
}

#[test]
fn loop_write_framed_indexed_reference_reads_back_with_index() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 7).unwrap();
    let r = BACnetObjectPropertyReference::new_indexed(
        oid,
        PropertyIdentifier::PRESENT_VALUE.to_raw(),
        3,
    );
    lo.write_property(
        PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE,
        None,
        framed_reference(&r),
        None,
    )
    .unwrap();
    // The optional array-index member is carried through to the read form.
    assert_eq!(
        lo.read_property(PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE, None)
            .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Enumerated(PropertyIdentifier::PRESENT_VALUE.to_raw()),
            PropertyValue::Unsigned(3),
        ])
    );
}

#[test]
fn loop_write_setpoint_reference_accepts_bacnetsetpointreference_frame() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 10).unwrap();
    let r = BACnetObjectPropertyReference::new(oid, PropertyIdentifier::PRESENT_VALUE.to_raw());
    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_setpoint_reference(&mut buf, &r);
    lo.write_property(
        PropertyIdentifier::SETPOINT_REFERENCE,
        None,
        PropertyValue::ApplicationData(buf.to_vec()),
        None,
    )
    .unwrap();
    assert_eq!(
        lo.read_property(PropertyIdentifier::SETPOINT_REFERENCE, None)
            .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Enumerated(PropertyIdentifier::PRESENT_VALUE.to_raw()),
        ])
    );
}

#[test]
fn loop_write_device_qualified_reference_rejected_and_preserves() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 7).unwrap();
    let prop_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();
    lo.set_controlled_variable_reference(BACnetObjectPropertyReference::new(oid, prop_raw));
    // [0] oid / [1] prop / [3] device: device qualification is not part of
    // the Loop reference production — INVALID_DATA_ENCODING, no change.
    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_object_property_reference(
        &mut buf,
        &BACnetObjectPropertyReference::new(oid, prop_raw),
    );
    bacnet_encoding::primitives::encode_ctx_object_id(
        &mut buf,
        3,
        &ObjectIdentifier::new(ObjectType::DEVICE, 77).unwrap(),
    );
    let err = lo
        .write_property(
            PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE,
            None,
            PropertyValue::ApplicationData(buf.to_vec()),
            None,
        )
        .unwrap_err();
    match err {
        Error::Protocol { class, code } => {
            assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
            assert_eq!(code, ErrorCode::INVALID_DATA_ENCODING.to_raw() as u32);
        }
        other => panic!("expected PROPERTY/INVALID_DATA_ENCODING, got {other:?}"),
    }
    assert_eq!(
        lo.read_property(PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE, None)
            .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Enumerated(prop_raw),
        ])
    );
}

#[test]
fn loop_write_empty_setpoint_frame_clears_reference() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 10).unwrap();
    let r = BACnetObjectPropertyReference::new(oid, PropertyIdentifier::PRESENT_VALUE.to_raw());
    let mut buf = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_setpoint_reference(&mut buf, &r);
    lo.write_property(
        PropertyIdentifier::SETPOINT_REFERENCE,
        None,
        PropertyValue::ApplicationData(buf.to_vec()),
        None,
    )
    .unwrap();
    assert_ne!(
        lo.read_property(PropertyIdentifier::SETPOINT_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );

    // 0x0E 0x0F: BACnetSetpointReference with its OPTIONAL member absent —
    // Clause 12.17 uses the stored Setpoint when no reference exists, so a
    // conformant peer clearing the reference this way must be accepted,
    // exactly like a Null write (pinned over the wire in the server's
    // `reference_writes` tests).
    lo.write_property(
        PropertyIdentifier::SETPOINT_REFERENCE,
        None,
        PropertyValue::ApplicationData(vec![0x0E, 0x0F]),
        None,
    )
    .unwrap();
    assert_eq!(
        lo.read_property(PropertyIdentifier::SETPOINT_REFERENCE, None)
            .unwrap(),
        PropertyValue::Null
    );
}

#[test]
fn loop_write_local_list_with_index_still_accepted() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 7).unwrap();
    let prop_raw = PropertyIdentifier::PRESENT_VALUE.to_raw();
    lo.write_property(
        PropertyIdentifier::SETPOINT_REFERENCE,
        None,
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Enumerated(prop_raw),
            PropertyValue::Unsigned(9),
        ]),
        None,
    )
    .unwrap();
    assert_eq!(
        lo.read_property(PropertyIdentifier::SETPOINT_REFERENCE, None)
            .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ObjectIdentifier(oid),
            PropertyValue::Enumerated(prop_raw),
            PropertyValue::Unsigned(9),
        ])
    );
}

// --- #985: COV_Increment, COV report contents, Present_Value writability ---

fn assert_property_error(error: Error, expected: ErrorCode) {
    assert!(
        matches!(error, Error::Protocol { class, code }
            if class == ErrorClass::PROPERTY.to_raw() as u32 && code == expected.to_raw() as u32),
        "expected PROPERTY/{expected:?}, got {error:?}"
    );
}

fn read(lo: &LoopObject, property: PropertyIdentifier) -> PropertyValue {
    lo.read_property(property, None).unwrap()
}

fn set_out_of_service(lo: &mut LoopObject, value: bool) {
    lo.write_property(
        PropertyIdentifier::OUT_OF_SERVICE,
        None,
        PropertyValue::Boolean(value),
        None,
    )
    .unwrap();
}

#[test]
fn loop_cov_increment_is_writable_validated_and_drives_cov() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    assert_eq!(
        read(&lo, PropertyIdentifier::COV_INCREMENT),
        PropertyValue::Real(0.0)
    );
    assert_eq!(lo.cov_increment(), Some(0.0));
    assert!(lo.is_writable_property(PropertyIdentifier::COV_INCREMENT));

    lo.write_property(
        PropertyIdentifier::COV_INCREMENT,
        None,
        PropertyValue::Real(2.5),
        None,
    )
    .unwrap();
    assert_eq!(lo.cov_increment(), Some(2.5));

    for (value, code) in [
        (PropertyValue::Real(-0.5), ErrorCode::VALUE_OUT_OF_RANGE),
        (PropertyValue::Real(f32::NAN), ErrorCode::VALUE_OUT_OF_RANGE),
        (
            PropertyValue::Real(f32::INFINITY),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
        (PropertyValue::Unsigned(3), ErrorCode::INVALID_DATA_TYPE),
    ] {
        assert_property_error(
            lo.write_property(PropertyIdentifier::COV_INCREMENT, None, value, None)
                .unwrap_err(),
            code,
        );
    }
    assert_eq!(
        read(&lo, PropertyIdentifier::COV_INCREMENT),
        PropertyValue::Real(2.5),
        "a refused write keeps the increment"
    );
}

#[test]
fn loop_present_value_is_writable_only_out_of_service() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    lo.set_present_value(10.0);
    // Writable for PICS purposes; the state gate decides each request.
    assert!(lo.is_writable_property(PropertyIdentifier::PRESENT_VALUE));
    assert_property_error(
        lo.write_property(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Real(42.0),
            None,
        )
        .unwrap_err(),
        ErrorCode::WRITE_ACCESS_DENIED,
    );
    assert_eq!(
        read(&lo, PropertyIdentifier::PRESENT_VALUE),
        PropertyValue::Real(10.0)
    );

    set_out_of_service(&mut lo, true);
    lo.write_property(
        PropertyIdentifier::PRESENT_VALUE,
        None,
        PropertyValue::Real(42.0),
        None,
    )
    .unwrap();
    assert_eq!(
        read(&lo, PropertyIdentifier::PRESENT_VALUE),
        PropertyValue::Real(42.0)
    );
    for (value, code) in [
        (PropertyValue::Real(f32::NAN), ErrorCode::VALUE_OUT_OF_RANGE),
        (PropertyValue::Unsigned(1), ErrorCode::INVALID_DATA_TYPE),
    ] {
        assert_property_error(
            lo.write_property(PropertyIdentifier::PRESENT_VALUE, None, value, None)
                .unwrap_err(),
            code,
        );
    }
    assert_eq!(
        read(&lo, PropertyIdentifier::PRESENT_VALUE),
        PropertyValue::Real(42.0)
    );

    set_out_of_service(&mut lo, false);
    assert_property_error(
        lo.write_property(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Real(7.0),
            None,
        )
        .unwrap_err(),
        ErrorCode::WRITE_ACCESS_DENIED,
    );
}

#[test]
fn loop_application_present_value_is_refused_out_of_service() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    lo.set_present_value_internal(PropertyValue::Real(12.0))
        .unwrap();
    assert_eq!(
        read(&lo, PropertyIdentifier::PRESENT_VALUE),
        PropertyValue::Real(12.0)
    );

    set_out_of_service(&mut lo, true);
    lo.write_property(
        PropertyIdentifier::PRESENT_VALUE,
        None,
        PropertyValue::Real(99.0),
        None,
    )
    .unwrap();
    assert_property_error(
        lo.set_present_value_internal(PropertyValue::Real(13.0))
            .unwrap_err(),
        ErrorCode::WRITE_ACCESS_DENIED,
    );
    assert_eq!(
        read(&lo, PropertyIdentifier::PRESENT_VALUE),
        PropertyValue::Real(99.0),
        "the client's simulated output survives the algorithm"
    );

    set_out_of_service(&mut lo, false);
    assert_property_error(
        lo.set_present_value_internal(PropertyValue::Real(f32::INFINITY))
            .unwrap_err(),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    lo.set_present_value_internal(PropertyValue::Real(14.0))
        .unwrap();
    assert_eq!(
        read(&lo, PropertyIdentifier::PRESENT_VALUE),
        PropertyValue::Real(14.0)
    );
}

#[test]
fn loop_controlled_variable_value_is_application_fed_and_read_only() {
    let mut lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    assert_eq!(
        read(&lo, PropertyIdentifier::CONTROLLED_VARIABLE_VALUE),
        PropertyValue::Real(0.0)
    );
    lo.set_controlled_variable_value(21.5);
    assert_eq!(
        read(&lo, PropertyIdentifier::CONTROLLED_VARIABLE_VALUE),
        PropertyValue::Real(21.5)
    );
    assert!(!lo.is_writable_property(PropertyIdentifier::CONTROLLED_VARIABLE_VALUE));
    for out_of_service in [false, true] {
        set_out_of_service(&mut lo, out_of_service);
        assert_property_error(
            lo.write_property(
                PropertyIdentifier::CONTROLLED_VARIABLE_VALUE,
                None,
                PropertyValue::Real(1.0),
                None,
            )
            .unwrap_err(),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
}

#[test]
fn loop_cov_reports_setpoint_and_controlled_variable_value() {
    use crate::traits::CovReportedProperty::Value;
    let lo = LoopObject::new(1, "LOOP-1", 62).unwrap();
    assert_eq!(
        lo.cov_reported_properties(),
        [
            Value(PropertyIdentifier::SETPOINT),
            Value(PropertyIdentifier::CONTROLLED_VARIABLE_VALUE),
        ]
    );
    let list = lo.property_list();
    for reported in lo.cov_reported_properties() {
        assert!(list.contains(&reported.property()));
        assert!(!reported.triggers(), "Table 13-1 reports them only");
    }
}
