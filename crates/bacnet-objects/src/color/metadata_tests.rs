//! The colour objects' property rows against the addendum's tables (Table
//! 12-X for Color, Table 12-Y for Color Temperature, #1474): which rows
//! exist, their conformance codes, and which take writes.

use super::*;
use crate::property_metadata::{PropertyConformance, PropertyWriteCapability};
use crate::traits::BACnetObject;
use bacnet_types::enums::{ErrorClass, ErrorCode, PropertyIdentifier as P};
use std::borrow::Cow;
use std::collections::HashSet;

use PropertyConformance::{Optional, RequiredRead, RequiredWrite};

fn assert_error(error: Error, expected: ErrorCode) {
    assert!(
        matches!(error, Error::Protocol { class, code }
            if class == ErrorClass::PROPERTY.to_raw() as u32
                && code == expected.to_raw() as u32),
        "expected {expected:?}, got {error:?}"
    );
}

/// Every row with its table code, in table order, Property_List last.
fn color_rows() -> Vec<(P, PropertyConformance)> {
    vec![
        (P::OBJECT_IDENTIFIER, RequiredRead),
        (P::OBJECT_NAME, RequiredRead),
        (P::OBJECT_TYPE, RequiredRead),
        (P::PRESENT_VALUE, RequiredWrite),
        (P::TRACKING_VALUE, RequiredRead),
        (P::COLOR_COMMAND, RequiredWrite),
        (P::IN_PROGRESS, RequiredRead),
        (P::DEFAULT_COLOR, RequiredRead),
        (P::DESCRIPTION, Optional),
        (P::DEFAULT_FADE_TIME, RequiredRead),
        (P::TRANSITION, Optional),
        (P::PROPERTY_LIST, RequiredRead),
    ]
}

fn color_temperature_rows() -> Vec<(P, PropertyConformance)> {
    vec![
        (P::OBJECT_IDENTIFIER, RequiredRead),
        (P::OBJECT_NAME, RequiredRead),
        (P::OBJECT_TYPE, RequiredRead),
        (P::PRESENT_VALUE, RequiredWrite),
        (P::TRACKING_VALUE, RequiredRead),
        (P::COLOR_COMMAND, RequiredWrite),
        (P::IN_PROGRESS, RequiredRead),
        (P::DEFAULT_COLOR_TEMPERATURE, RequiredRead),
        (P::DESCRIPTION, Optional),
        (P::DEFAULT_FADE_TIME, RequiredRead),
        (P::DEFAULT_RAMP_RATE, RequiredRead),
        (P::DEFAULT_STEP_INCREMENT, RequiredRead),
        (P::MIN_PRES_VALUE, Optional),
        (P::MAX_PRES_VALUE, Optional),
        (P::TRANSITION, Optional),
        (P::PROPERTY_LIST, RequiredRead),
    ]
}

/// The rows each object takes writes for.
const COLOR_WRITABLE: &[P] = &[
    P::PRESENT_VALUE,
    P::COLOR_COMMAND,
    P::DEFAULT_COLOR,
    P::DESCRIPTION,
    P::DEFAULT_FADE_TIME,
    P::TRANSITION,
];

const COLOR_TEMPERATURE_WRITABLE: &[P] = &[
    P::PRESENT_VALUE,
    P::COLOR_COMMAND,
    P::DEFAULT_COLOR_TEMPERATURE,
    P::DESCRIPTION,
    P::DEFAULT_FADE_TIME,
    P::DEFAULT_RAMP_RATE,
    P::DEFAULT_STEP_INCREMENT,
    P::TRANSITION,
];

/// An object, its rows with their codes, and the rows it takes writes for.
type Case = (
    Box<dyn BACnetObject>,
    Vec<(P, PropertyConformance)>,
    &'static [P],
);

fn objects() -> [Case; 2] {
    [
        (
            Box::new(ColorObject::new(1, "CLR-1").unwrap()),
            color_rows(),
            COLOR_WRITABLE,
        ),
        (
            Box::new(ColorTemperatureObject::new(1, "CT-1").unwrap()),
            color_temperature_rows(),
            COLOR_TEMPERATURE_WRITABLE,
        ),
    ]
}

#[test]
fn rows_and_codes_match_the_addendum_tables() {
    for (object, rows, writable) in objects() {
        let metadata = object.property_metadata();
        assert!(matches!(metadata, Cow::Borrowed(_)));
        let found: Vec<_> = metadata
            .iter()
            .map(|row| (row.property_identifier, row.conformance))
            .collect();
        assert_eq!(found, rows);
        let all: Vec<_> = rows[..rows.len() - 1].iter().map(|&(p, _)| p).collect();
        assert_eq!(object.property_list().as_ref(), all);
        let required: Vec<_> = rows
            .iter()
            .filter(|(_, code)| code.is_required())
            .map(|&(p, _)| p)
            .collect();
        assert_eq!(object.required_properties().as_ref(), required);
        assert_eq!(
            rows.iter().map(|&(p, _)| p).collect::<HashSet<_>>().len(),
            rows.len()
        );
        assert!(!object.is_createable());
        assert!(object.is_deleteable());
        assert!(object.supports_cov());
        for row in metadata.iter() {
            let p = row.property_identifier;
            assert_eq!(row.presence_condition, None);
            let capability = if writable.contains(&p) {
                PropertyWriteCapability::Always
            } else {
                PropertyWriteCapability::ReadOnly
            };
            assert_eq!(row.write_capability, capability, "{p:?}");
            assert_eq!(object.is_writable_property(p), capability.is_writable());
            object.read_property(p, None).unwrap();
            assert_eq!(object.is_array_property(p), p == P::PROPERTY_LIST, "{p:?}");
        }
    }
}

#[test]
fn neither_object_serves_status_or_service_rows() {
    // Neither table has these rows, nor a priority array or COV_Increment.
    for (mut object, _, _) in objects() {
        for p in [
            P::STATUS_FLAGS,
            P::EVENT_STATE,
            P::RELIABILITY,
            P::OUT_OF_SERVICE,
            P::PRIORITY_ARRAY,
            P::COV_INCREMENT,
            P::DEVICE_TYPE,
        ] {
            assert!(!object.property_list().contains(&p), "{p:?}");
            assert!(!object.is_writable_property(p), "{p:?}");
            assert_error(
                object.read_property(p, None).unwrap_err(),
                ErrorCode::UNKNOWN_PROPERTY,
            );
            assert_error(
                object
                    .write_property(p, None, PropertyValue::Boolean(true), None)
                    .unwrap_err(),
                ErrorCode::UNKNOWN_PROPERTY,
            );
        }
    }
}

#[test]
fn read_only_rows_deny_even_their_own_value() {
    for (mut object, rows, writable) in objects() {
        for (p, _) in rows {
            if writable.contains(&p) || p == P::PROPERTY_LIST {
                continue;
            }
            let value = object.read_property(p, None).unwrap();
            assert_error(
                object.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::WRITE_ACCESS_DENIED,
            );
        }
    }
}

#[test]
fn writable_rows_take_their_own_value_back() {
    for (mut object, _, writable) in objects() {
        for &p in writable {
            // Color_Command reads NONE until written, and NONE can't be
            // written, so STOP goes instead.
            let value = if p == P::COLOR_COMMAND {
                PropertyValue::ApplicationData(vec![0x09, 0x06])
            } else {
                object.read_property(p, None).unwrap()
            };
            object.write_property(p, None, value.clone(), None).unwrap();
            assert_eq!(object.read_property(p, None).unwrap(), value, "{p:?}");
        }
    }
}

#[test]
fn indexed_property_list_omits_the_identity_rows() {
    for (object, rows, _) in objects() {
        let wire: Vec<_> = rows
            .iter()
            .map(|&(p, _)| p)
            .filter(|p| {
                !matches!(
                    *p,
                    P::OBJECT_IDENTIFIER | P::OBJECT_NAME | P::OBJECT_TYPE | P::PROPERTY_LIST
                )
            })
            .map(|p| PropertyValue::Enumerated(p.to_raw()))
            .collect();
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
        assert_error(
            object
                .read_property(P::PROPERTY_LIST, Some(wire.len() as u32 + 1))
                .unwrap_err(),
            ErrorCode::INVALID_ARRAY_INDEX,
        );
    }
}
