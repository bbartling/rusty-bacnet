use super::*;
use crate::property_metadata::PropertyWriteCapability;
use crate::traits::BACnetObject;
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;
use std::collections::HashSet;

fn assert_error(error: Error, expected: ErrorCode) {
    assert!(
        matches!(error, Error::Protocol { class, code }
            if class == ErrorClass::PROPERTY.to_raw() as u32
                && code == expected.to_raw() as u32),
        "expected {expected:?}, got {error:?}"
    );
}

const ALL: [P; 19] = [
    P::OBJECT_IDENTIFIER,
    P::OBJECT_NAME,
    P::DESCRIPTION,
    P::OBJECT_TYPE,
    P::PRESENT_VALUE,
    P::UNITS,
    P::SCALE_FACTOR,
    P::ADJUST_VALUE,
    P::COUNT,
    P::UPDATE_TIME,
    P::COUNT_CHANGE_TIME,
    P::COUNT_BEFORE_CHANGE,
    P::COV_INCREMENT,
    P::COV_PERIOD,
    P::INPUT_REFERENCE,
    P::STATUS_FLAGS,
    P::EVENT_STATE,
    P::OUT_OF_SERVICE,
    P::RELIABILITY,
];

const REQUIRED: [P; 15] = [
    P::OBJECT_IDENTIFIER,
    P::OBJECT_NAME,
    P::OBJECT_TYPE,
    P::PRESENT_VALUE,
    P::UNITS,
    P::SCALE_FACTOR,
    P::ADJUST_VALUE,
    P::COUNT,
    P::UPDATE_TIME,
    P::COUNT_CHANGE_TIME,
    P::COUNT_BEFORE_CHANGE,
    P::STATUS_FLAGS,
    P::EVENT_STATE,
    P::OUT_OF_SERVICE,
    P::PROPERTY_LIST,
];

/// Rows with no network write route; a write of their own readback is denied.
const READ_ONLY: [P; 9] = [
    P::UNITS,
    P::COUNT,
    P::UPDATE_TIME,
    P::COUNT_CHANGE_TIME,
    P::COUNT_BEFORE_CHANGE,
    P::COV_PERIOD,
    P::STATUS_FLAGS,
    P::EVENT_STATE,
    P::RELIABILITY,
];

#[test]
fn property_metadata_pulse_converter_exact_sets_readable_rows_and_indexed_list() {
    let object = PulseConverterObject::new(1, "PC-1", 62).unwrap();
    let metadata = object.property_metadata();
    assert!(matches!(metadata, Cow::Borrowed(_)));
    assert_eq!(metadata.len(), ALL.len() + 1);
    assert_eq!(object.property_list().as_ref(), ALL);
    assert_eq!(object.required_properties().as_ref(), REQUIRED);
    assert_eq!(
        metadata
            .iter()
            .map(|row| row.property_identifier)
            .collect::<HashSet<_>>()
            .len(),
        metadata.len()
    );
    assert!(!object.is_createable());
    assert!(object.is_deleteable());
    assert!(object.supports_cov());
    for row in metadata.iter() {
        assert_eq!(row.presence_condition, None);
        let expected = if row.property_identifier == P::ADJUST_VALUE {
            RequiredWrite
        } else if REQUIRED.contains(&row.property_identifier) {
            RequiredRead
        } else {
            Optional
        };
        assert_eq!(row.conformance, expected, "{:?}", row.property_identifier);
        object.read_property(row.property_identifier, None).unwrap();
    }

    let wire: Vec<_> = ALL
        .iter()
        .filter(|&&p| !matches!(p, P::OBJECT_IDENTIFIER | P::OBJECT_NAME | P::OBJECT_TYPE))
        .map(|p| PropertyValue::Enumerated(p.to_raw()))
        .collect();
    assert!(object.is_array_property(P::PROPERTY_LIST));
    assert_eq!(
        object.read_property(P::PROPERTY_LIST, None).unwrap(),
        PropertyValue::List(wire.clone())
    );
    assert_eq!(
        object.read_property(P::PROPERTY_LIST, Some(0)).unwrap(),
        PropertyValue::Unsigned(wire.len() as u64)
    );
    for (index, value) in wire.iter().enumerate() {
        assert_eq!(
            object
                .read_property(P::PROPERTY_LIST, Some(index as u32 + 1))
                .unwrap(),
            *value
        );
    }
    for index in [wire.len() as u32 + 1, u32::MAX] {
        assert_error(
            object
                .read_property(P::PROPERTY_LIST, Some(index))
                .unwrap_err(),
            ErrorCode::INVALID_ARRAY_INDEX,
        );
    }

    assert_eq!(
        object.read_property(P::PRESENT_VALUE, None).unwrap(),
        PropertyValue::Real(0.0)
    );
    assert_eq!(
        object.read_property(P::SCALE_FACTOR, None).unwrap(),
        PropertyValue::Real(1.0)
    );
    assert_eq!(
        object.read_property(P::INPUT_REFERENCE, None).unwrap(),
        PropertyValue::Null
    );
    assert_eq!(
        object.read_property(P::COV_PERIOD, None).unwrap(),
        PropertyValue::Unsigned(0)
    );
    assert_eq!(object.cov_increment(), Some(0.0));
    for p in [
        P::INPUT_REFERENCE,
        P::PRESENT_VALUE,
        P::COUNT,
        P::UPDATE_TIME,
        P::COUNT_CHANGE_TIME,
    ] {
        assert!(!object.is_array_property(p), "{p:?}");
    }
}

#[test]
fn property_metadata_pulse_converter_write_capabilities_match_dispatch() {
    let always = [
        P::DESCRIPTION,
        P::OUT_OF_SERVICE,
        P::SCALE_FACTOR,
        P::ADJUST_VALUE,
        P::INPUT_REFERENCE,
        P::COV_INCREMENT,
    ];
    for out_of_service in [false, true] {
        let mut object = PulseConverterObject::new(1, "PC-1", 62).unwrap();
        object
            .write_property(
                P::OUT_OF_SERVICE,
                None,
                PropertyValue::Boolean(out_of_service),
                None,
            )
            .unwrap();
        let original = object.property_metadata().into_owned();
        for row in &original {
            let p = row.property_identifier;
            let capability = if always.contains(&p) {
                PropertyWriteCapability::Always
            } else if p == P::PRESENT_VALUE {
                PropertyWriteCapability::WhenOutOfService
            } else {
                PropertyWriteCapability::ReadOnly
            };
            assert_eq!(row.write_capability, capability, "{p:?}");
            assert_eq!(
                object.is_writable_property(p),
                capability.is_writable(),
                "{p:?}"
            );
            let value = object.read_property(p, None).unwrap();
            let result = object.write_property(p, None, value, None);
            if capability == PropertyWriteCapability::Always
                || (capability == PropertyWriteCapability::WhenOutOfService && out_of_service)
            {
                result.unwrap();
            } else {
                assert_error(result.unwrap_err(), ErrorCode::WRITE_ACCESS_DENIED);
            }
        }
        // Object_Name has no network write route: a rename falls through
        // to WRITE_ACCESS_DENIED even with a well-formed value.
        assert!(!object.is_writable_property(P::OBJECT_NAME));
        assert_error(
            object
                .write_property(
                    P::OBJECT_NAME,
                    None,
                    PropertyValue::CharacterString("renamed".into()),
                    None,
                )
                .unwrap_err(),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
        assert_eq!(object.property_metadata().as_ref(), original);
    }
}

#[test]
fn property_metadata_pulse_converter_present_value_oos_gate_pins() {
    // In-service writes are denied before value validation (D5): even a
    // mistyped or non-finite value reports WRITE_ACCESS_DENIED, not a
    // datatype or range error, and the stored value is untouched.
    let mut object = PulseConverterObject::new(1, "PC-1", 62).unwrap();
    assert!(object.is_writable_property(P::PRESENT_VALUE));
    for value in [
        PropertyValue::Real(12.5),
        PropertyValue::Unsigned(12),
        PropertyValue::Real(f32::NAN),
    ] {
        assert_error(
            object
                .write_property(P::PRESENT_VALUE, None, value, None)
                .unwrap_err(),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
    assert_eq!(
        object.read_property(P::PRESENT_VALUE, None).unwrap(),
        PropertyValue::Real(0.0)
    );
    // Out of service, a finite Real round-trips; mistyped and
    // non-finite values are rejected past the gate.
    object
        .write_property(P::OUT_OF_SERVICE, None, PropertyValue::Boolean(true), None)
        .unwrap();
    object
        .write_property(P::PRESENT_VALUE, None, PropertyValue::Real(12.5), None)
        .unwrap();
    assert_eq!(
        object.read_property(P::PRESENT_VALUE, None).unwrap(),
        PropertyValue::Real(12.5)
    );
    assert_error(
        object
            .write_property(P::PRESENT_VALUE, None, PropertyValue::Unsigned(12), None)
            .unwrap_err(),
        ErrorCode::INVALID_DATA_TYPE,
    );
    assert_error(
        object
            .write_property(
                P::PRESENT_VALUE,
                None,
                PropertyValue::Real(f32::INFINITY),
                None,
            )
            .unwrap_err(),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_eq!(
        object.read_property(P::PRESENT_VALUE, None).unwrap(),
        PropertyValue::Real(12.5)
    );
}

#[test]
fn property_metadata_pulse_converter_writes_store_verbatim_with_range_gates() {
    for out_of_service in [false, true] {
        let mut object = PulseConverterObject::new(1, "PC-1", 62).unwrap();
        object
            .write_property(
                P::OUT_OF_SERVICE,
                None,
                PropertyValue::Boolean(out_of_service),
                None,
            )
            .unwrap();
        object
            .write_property(P::SCALE_FACTOR, None, PropertyValue::Real(2.5), None)
            .unwrap();
        assert_eq!(
            object.read_property(P::SCALE_FACTOR, None).unwrap(),
            PropertyValue::Real(2.5)
        );
        // 0.5 / 2.5 truncates to zero, so Count stays put.
        object
            .write_property(P::ADJUST_VALUE, None, PropertyValue::Real(0.5), None)
            .unwrap();
        assert_eq!(
            object.read_property(P::ADJUST_VALUE, None).unwrap(),
            PropertyValue::Real(0.5)
        );
        object
            .write_property(P::COV_INCREMENT, None, PropertyValue::Real(0.5), None)
            .unwrap();
        assert_eq!(
            object.read_property(P::COV_INCREMENT, None).unwrap(),
            PropertyValue::Real(0.5)
        );
        assert_eq!(object.cov_increment(), Some(0.5));
        // Non-finite and negative values are refused without touching state.
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            for p in [P::SCALE_FACTOR, P::ADJUST_VALUE] {
                assert_error(
                    object
                        .write_property(p, None, PropertyValue::Real(value), None)
                        .unwrap_err(),
                    ErrorCode::VALUE_OUT_OF_RANGE,
                );
            }
            assert_error(
                object
                    .write_property(P::COV_INCREMENT, None, PropertyValue::Real(value), None)
                    .unwrap_err(),
                ErrorCode::VALUE_OUT_OF_RANGE,
            );
        }
        assert_error(
            object
                .write_property(P::COV_INCREMENT, None, PropertyValue::Real(-1.0), None)
                .unwrap_err(),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_eq!(
            object.read_property(P::SCALE_FACTOR, None).unwrap(),
            PropertyValue::Real(2.5)
        );
        // Input_Reference stores a local reference, its Clause 21 members
        // ([0] accumulator 1, [1] present-value), and Null clears it.
        let reference =
            PropertyValue::ApplicationData(vec![0x0C, 0x05, 0xC0, 0x00, 0x01, 0x19, 0x55]);
        object
            .write_property(P::INPUT_REFERENCE, None, reference.clone(), None)
            .unwrap();
        assert_eq!(
            object.read_property(P::INPUT_REFERENCE, None).unwrap(),
            reference
        );
        object
            .write_property(P::INPUT_REFERENCE, None, PropertyValue::Null, None)
            .unwrap();
        assert_eq!(
            object.read_property(P::INPUT_REFERENCE, None).unwrap(),
            PropertyValue::Null
        );
        // Mistyped values are rejected without changing state.
        for (p, value) in [
            (P::SCALE_FACTOR, PropertyValue::Unsigned(1)),
            (P::ADJUST_VALUE, PropertyValue::Unsigned(1)),
            (P::COV_INCREMENT, PropertyValue::Null),
            (P::INPUT_REFERENCE, PropertyValue::Unsigned(1)),
            (P::DESCRIPTION, PropertyValue::Unsigned(1)),
            (P::OUT_OF_SERVICE, PropertyValue::Unsigned(1)),
        ] {
            assert_error(
                object.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::INVALID_DATA_TYPE,
            );
        }
        // Rows with no network write route deny even their readback.
        for p in READ_ONLY {
            let value = object.read_property(p, None).unwrap();
            assert_error(
                object.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::WRITE_ACCESS_DENIED,
            );
            assert!(!object.is_writable_property(p));
        }
    }
}

#[test]
fn property_metadata_pulse_converter_unserved_rows_stay_unknown() {
    // Optional Table 12-27 rows the object does not implement, plus a row
    // from the Accumulator's table that Table 12-27 does not define.
    let mut object = PulseConverterObject::new(1, "PC-1", 62).unwrap();
    for p in [
        P::NOTIFICATION_CLASS,
        P::HIGH_LIMIT,
        P::RELIABILITY_EVALUATION_INHIBIT,
        P::DEVICE_TYPE,
    ] {
        assert!(!object.is_writable_property(p));
        assert_error(
            object.read_property(p, None).unwrap_err(),
            ErrorCode::UNKNOWN_PROPERTY,
        );
        assert_error(
            object
                .write_property(p, None, PropertyValue::Null, None)
                .unwrap_err(),
            ErrorCode::UNKNOWN_PROPERTY,
        );
    }
}
