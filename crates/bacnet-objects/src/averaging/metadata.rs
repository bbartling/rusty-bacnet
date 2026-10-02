use super::AveragingObject;
use std::borrow::Cow;

use bacnet_types::enums::PropertyIdentifier as P;

use crate::property_metadata::{
    PropertyConformance::{Optional, RequiredRead, RequiredWrite},
    PropertyMetadata,
    PropertyWriteCapability::{Always, ReadOnly},
};

// Canonical effective rows for Averaging (type 18, Clause 12.5 Table 12-5).
// Order preserves the legacy 15-property projection; PROPERTY_LIST is
// appended so the projection helper omits it while required_properties keeps
// it. Only implemented rows are described: table rows the object does not
// serve (Window_Interval, Window_Samples, timestamps, Variance_Value, audit,
// tags, profile rows) stay absent until dispatch exists.
// Object_Property_Reference carries the table R code and the implementation
// accepts network writes, so it is RequiredWrite/Always. Attempted_Samples
// carries the table W1 code but dispatch has no write arm (not even the
// table's zero-reset), so the row mirrors dispatch as RequiredRead/ReadOnly
// rather than advertising a route write_property rejects (Tracking_Value R1
// precedent). Table 12-5 has no Present_Value, Status_Flags, Out_Of_Service,
// Reliability or Event_State, so there are no such rows (#1064 removed the
// rows the 0.1.0 import carried).
const BASE: &[PropertyMetadata] = &[
    PropertyMetadata::new(P::OBJECT_IDENTIFIER, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OBJECT_NAME, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::DESCRIPTION, Optional, None, Always),
    PropertyMetadata::new(P::OBJECT_TYPE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::MINIMUM_VALUE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::MAXIMUM_VALUE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::AVERAGE_VALUE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::ATTEMPTED_SAMPLES, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::VALID_SAMPLES, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OBJECT_PROPERTY_REFERENCE, RequiredWrite, None, Always),
    PropertyMetadata::new(P::PROPERTY_LIST, RequiredRead, None, ReadOnly),
];

pub(super) fn for_object(_object: &AveragingObject) -> Cow<'_, [PropertyMetadata]> {
    Cow::Borrowed(BASE)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn property_metadata_averaging_exact_sets_readable_rows_and_indexed_list() {
        let object = AveragingObject::new(1, "AVG-1").unwrap();
        let all = [
            P::OBJECT_IDENTIFIER,
            P::OBJECT_NAME,
            P::DESCRIPTION,
            P::OBJECT_TYPE,
            P::MINIMUM_VALUE,
            P::MAXIMUM_VALUE,
            P::AVERAGE_VALUE,
            P::ATTEMPTED_SAMPLES,
            P::VALID_SAMPLES,
            P::OBJECT_PROPERTY_REFERENCE,
        ];
        let required = [
            P::OBJECT_IDENTIFIER,
            P::OBJECT_NAME,
            P::OBJECT_TYPE,
            P::MINIMUM_VALUE,
            P::MAXIMUM_VALUE,
            P::AVERAGE_VALUE,
            P::ATTEMPTED_SAMPLES,
            P::VALID_SAMPLES,
            P::OBJECT_PROPERTY_REFERENCE,
            P::PROPERTY_LIST,
        ];
        let metadata = object.property_metadata();
        assert!(matches!(metadata, Cow::Borrowed(_)));
        assert_eq!(metadata.len(), 11);
        assert_eq!(object.property_list().as_ref(), all);
        assert_eq!(object.required_properties().as_ref(), required);
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
        assert!(!object.supports_cov());
        for row in metadata.iter() {
            assert_eq!(row.presence_condition, None);
            let expected = if row.property_identifier == P::OBJECT_PROPERTY_REFERENCE {
                RequiredWrite
            } else if required.contains(&row.property_identifier) {
                RequiredRead
            } else {
                Optional
            };
            assert_eq!(row.conformance, expected, "{:?}", row.property_identifier);
            object.read_property(row.property_identifier, None).unwrap();
        }
        // Table 12-5 has no Present_Value, Status_Flags, Out_Of_Service,
        // Reliability or Event_State row (#1064).
        for p in [
            P::PRESENT_VALUE,
            P::STATUS_FLAGS,
            P::OUT_OF_SERVICE,
            P::RELIABILITY,
            P::EVENT_STATE,
        ] {
            assert_error(
                object.read_property(p, None).unwrap_err(),
                ErrorCode::UNKNOWN_PROPERTY,
            );
        }
        let wire: Vec<_> = all
            .iter()
            .filter(|&&p| !matches!(p, P::OBJECT_IDENTIFIER | P::OBJECT_NAME | P::OBJECT_TYPE))
            .map(|p| PropertyValue::Enumerated(p.to_raw()))
            .collect();
        assert_eq!(wire.len(), 7);
        assert!(object.is_array_property(P::PROPERTY_LIST));
        assert_eq!(
            object.read_property(P::PROPERTY_LIST, None).unwrap(),
            PropertyValue::List(wire.clone())
        );
        assert_eq!(
            object.read_property(P::PROPERTY_LIST, Some(0)).unwrap(),
            PropertyValue::Unsigned(7)
        );
        for (index, value) in wire.iter().enumerate() {
            assert_eq!(
                object
                    .read_property(P::PROPERTY_LIST, Some(index as u32 + 1))
                    .unwrap(),
                *value
            );
        }
        for index in [8, u32::MAX] {
            assert_error(
                object
                    .read_property(P::PROPERTY_LIST, Some(index))
                    .unwrap_err(),
                ErrorCode::INVALID_ARRAY_INDEX,
            );
        }
    }

    #[test]
    fn property_metadata_averaging_write_capabilities_match_dispatch() {
        let mut object = AveragingObject::new(1, "AVG-1").unwrap();
        let original = object.property_metadata().into_owned();
        for row in &original {
            let p = row.property_identifier;
            let capability = match p {
                P::DESCRIPTION | P::OBJECT_PROPERTY_REFERENCE => Always,
                _ => ReadOnly,
            };
            assert_eq!(row.write_capability, capability, "{p:?}");
            assert_eq!(
                object.is_writable_property(p),
                capability.is_writable(),
                "{p:?}"
            );
            let value = object.read_property(p, None).unwrap();
            let result = object.write_property(p, None, value, None);
            if capability.is_writable() {
                result.unwrap();
            } else {
                assert_error(result.unwrap_err(), ErrorCode::WRITE_ACCESS_DENIED);
            }
        }
        // OBJECT_NAME has no network write route: a rename falls through
        // to WRITE_ACCESS_DENIED even with a well-formed value.
        assert!(!object.is_writable_property(P::OBJECT_NAME));
        assert_error(
            object
                .write_property(
                    P::OBJECT_NAME,
                    None,
                    PropertyValue::CharacterString("AVG-2".into()),
                    None,
                )
                .unwrap_err(),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
        // Attempted_Samples carries the table W1 code but dispatch has no
        // write arm (not even the zero-reset), so even Unsigned(0) is
        // denied and the row stays ReadOnly.
        assert!(!object.is_writable_property(P::ATTEMPTED_SAMPLES));
        assert_error(
            object
                .write_property(P::ATTEMPTED_SAMPLES, None, PropertyValue::Unsigned(0), None)
                .unwrap_err(),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
        // The statistics scalars have no network write route.
        for p in [
            P::MINIMUM_VALUE,
            P::MAXIMUM_VALUE,
            P::AVERAGE_VALUE,
            P::VALID_SAMPLES,
        ] {
            let value = object.read_property(p, None).unwrap();
            assert_error(
                object.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::WRITE_ACCESS_DENIED,
            );
            assert!(!object.is_writable_property(p));
        }
        // Description rejects a mistyped value without changing state.
        assert_error(
            object
                .write_property(P::DESCRIPTION, None, PropertyValue::Unsigned(1), None)
                .unwrap_err(),
            ErrorCode::INVALID_DATA_TYPE,
        );
        // Unserved Table 12-5 rows, and the rows the table doesn't define
        // (#1064), stay unknown on both paths.
        for p in [
            P::PRESENT_VALUE,
            P::STATUS_FLAGS,
            P::OUT_OF_SERVICE,
            P::RELIABILITY,
            P::EVENT_STATE,
            P::WINDOW_INTERVAL,
            P::WINDOW_SAMPLES,
            P::MINIMUM_VALUE_TIMESTAMP,
            P::MAXIMUM_VALUE_TIMESTAMP,
            P::VARIANCE_VALUE,
            P::ALL,
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
        assert_eq!(object.property_metadata().as_ref(), original);
    }
}
