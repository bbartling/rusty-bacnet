use super::*;
use crate::property_metadata::{PropertyPresenceCondition, PropertyWriteCapability};
use crate::traits::BACnetObject;
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType};
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

/// The zone's intrinsic-reporting rows (#1305), in metadata order.
const ZONE_EVENT_ROWS: [P; 10] = [
    P::TIME_DELAY,
    P::NOTIFICATION_CLASS,
    P::ALARM_VALUES,
    P::EVENT_ENABLE,
    P::ACKED_TRANSITIONS,
    P::NOTIFY_TYPE,
    P::EVENT_TIME_STAMPS,
    P::EVENT_MESSAGE_TEXTS,
    P::EVENT_DETECTION_ENABLE,
    P::TIME_DELAY_NORMAL,
];

fn assert_exact_sets(object: &dyn BACnetObject, all: &[P], required: &[P]) {
    let metadata = object.property_metadata();
    assert!(matches!(metadata, Cow::Borrowed(_)));
    assert_eq!(metadata.len(), all.len() + 1);
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
    for row in metadata.iter() {
        assert_eq!(
            row.presence_condition,
            ZONE_EVENT_ROWS
                .contains(&row.property_identifier)
                .then_some(PropertyPresenceCondition::IntrinsicReporting),
            "{:?}",
            row.property_identifier
        );
        let expected = if (row.property_identifier == P::PRESENT_VALUE
            && object.object_identifier().object_type() == ObjectType::ACCESS_DOOR)
            || row.property_identifier == P::GLOBAL_IDENTIFIER
        {
            RequiredWrite
        } else if required.contains(&row.property_identifier) {
            RequiredRead
        } else {
            Optional
        };
        assert_eq!(row.conformance, expected, "{:?}", row.property_identifier);
        object.read_property(row.property_identifier, None).unwrap();
    }
}

fn assert_indexed_property_list(object: &dyn BACnetObject, all: &[P]) {
    let wire: Vec<_> = all
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
}

#[test]
fn property_metadata_access_door_exact_sets_readable_rows_and_indexed_list() {
    let object = AccessDoorObject::new(1, "DOOR-1").unwrap();
    let all = [
        P::OBJECT_IDENTIFIER,
        P::OBJECT_NAME,
        P::DESCRIPTION,
        P::OBJECT_TYPE,
        P::PRESENT_VALUE,
        P::DOOR_STATUS,
        P::LOCK_STATUS,
        P::SECURED_STATUS,
        P::DOOR_ALARM_STATE,
        P::DOOR_MEMBERS,
        P::STATUS_FLAGS,
        P::OUT_OF_SERVICE,
        P::RELIABILITY,
        P::EVENT_STATE,
        P::PRIORITY_ARRAY,
        P::RELINQUISH_DEFAULT,
        P::DOOR_PULSE_TIME,
        P::DOOR_EXTENDED_PULSE_TIME,
        P::DOOR_OPEN_TOO_LONG_TIME,
        P::CURRENT_COMMAND_PRIORITY,
    ];
    let required = [
        P::OBJECT_IDENTIFIER,
        P::OBJECT_NAME,
        P::OBJECT_TYPE,
        P::PRESENT_VALUE,
        P::STATUS_FLAGS,
        P::OUT_OF_SERVICE,
        P::RELIABILITY,
        P::EVENT_STATE,
        P::PRIORITY_ARRAY,
        P::RELINQUISH_DEFAULT,
        P::DOOR_PULSE_TIME,
        P::DOOR_EXTENDED_PULSE_TIME,
        P::DOOR_OPEN_TOO_LONG_TIME,
        P::CURRENT_COMMAND_PRIORITY,
        P::PROPERTY_LIST,
    ];
    assert_exact_sets(&object, &all, &required);
    assert_indexed_property_list(&object, &all);
    assert!(object.supports_cov());
    assert_eq!(
        object.read_property(P::PRESENT_VALUE, None).unwrap(),
        PropertyValue::Enumerated(0)
    );
    assert_eq!(
        object.read_property(P::RELINQUISH_DEFAULT, None).unwrap(),
        PropertyValue::Enumerated(0)
    );
    assert_eq!(
        object.read_property(P::EVENT_STATE, None).unwrap(),
        PropertyValue::Enumerated(0)
    );
    assert_eq!(
        object.read_property(P::DOOR_MEMBERS, None).unwrap(),
        PropertyValue::List(vec![])
    );
    // Priority_Array and Door_Members are BACnetARRAYs (Table 12-30), so
    // the service gate admits an index on both (#1169).
    assert!(object.is_array_property(P::PRIORITY_ARRAY));
    assert_eq!(
        object.read_property(P::PRIORITY_ARRAY, Some(0)).unwrap(),
        PropertyValue::Unsigned(16)
    );
    assert_eq!(
        object.read_property(P::PRIORITY_ARRAY, Some(1)).unwrap(),
        PropertyValue::Null
    );
    assert!(object.is_array_property(P::DOOR_MEMBERS));
    assert!(!object.is_array_property(P::DOOR_STATUS));
    // The #1073 rows: the three times in tenths of a second, and no
    // command priority while Present_Value is the default.
    for (p, tenths) in [
        (P::DOOR_PULSE_TIME, 50),
        (P::DOOR_EXTENDED_PULSE_TIME, 150),
        (P::DOOR_OPEN_TOO_LONG_TIME, 300),
    ] {
        assert_eq!(
            object.read_property(p, None).unwrap(),
            PropertyValue::Unsigned(tenths)
        );
        assert!(!object.is_array_property(p));
    }
    assert_eq!(
        object
            .read_property(P::CURRENT_COMMAND_PRIORITY, None)
            .unwrap(),
        PropertyValue::Null
    );
}

#[test]
fn property_metadata_access_point_exact_sets_readable_rows_and_indexed_list() {
    let object = AccessPointObject::new(1, "AP-1").unwrap();
    let all = [
        P::OBJECT_IDENTIFIER,
        P::OBJECT_NAME,
        P::DESCRIPTION,
        P::OBJECT_TYPE,
        P::ACCESS_EVENT,
        P::ACCESS_EVENT_TAG,
        P::ACCESS_EVENT_TIME,
        P::ACCESS_DOORS,
        P::EVENT_STATE,
        P::STATUS_FLAGS,
        P::OUT_OF_SERVICE,
        P::RELIABILITY,
        // The Table 12-36 required rows #1284 added.
        P::AUTHENTICATION_STATUS,
        P::ACCESS_EVENT_CREDENTIAL,
        // The Table 12-36 required rows #1307 added.
        P::ACTIVE_AUTHENTICATION_POLICY,
        P::NUMBER_OF_AUTHENTICATION_POLICIES,
        P::AUTHORIZATION_MODE,
        P::PRIORITY_FOR_WRITING,
    ];
    let required = [
        P::OBJECT_IDENTIFIER,
        P::OBJECT_NAME,
        P::OBJECT_TYPE,
        P::ACCESS_EVENT,
        P::ACCESS_EVENT_TAG,
        P::ACCESS_EVENT_TIME,
        P::ACCESS_DOORS,
        P::EVENT_STATE,
        P::STATUS_FLAGS,
        P::OUT_OF_SERVICE,
        P::RELIABILITY,
        P::AUTHENTICATION_STATUS,
        P::ACCESS_EVENT_CREDENTIAL,
        P::ACTIVE_AUTHENTICATION_POLICY,
        P::NUMBER_OF_AUTHENTICATION_POLICIES,
        P::AUTHORIZATION_MODE,
        P::PRIORITY_FOR_WRITING,
        P::PROPERTY_LIST,
    ];
    assert_exact_sets(&object, &all, &required);
    assert_indexed_property_list(&object, &all);
    // Table 13-1 has an Access Point row (#1061).
    assert!(object.supports_cov());
    // Table 12-36 has no Present_Value row (#1064).
    assert_error(
        object.read_property(P::PRESENT_VALUE, None).unwrap_err(),
        ErrorCode::UNKNOWN_PROPERTY,
    );
    assert_eq!(
        object.read_property(P::ACCESS_EVENT, None).unwrap(),
        PropertyValue::Enumerated(0)
    );
    assert_eq!(
        object.read_property(P::ACCESS_EVENT_TAG, None).unwrap(),
        PropertyValue::Unsigned(0)
    );
    // The unspecified date and time as the datetime [2] choice (#1133).
    assert_eq!(
        object.read_property(P::ACCESS_EVENT_TIME, None).unwrap(),
        PropertyValue::ApplicationData(vec![
            0x2E, 0xA4, 0xFF, 0xFF, 0xFF, 0xFF, 0xB4, 0xFF, 0xFF, 0xFF, 0xFF, 0x2F
        ])
    );
    assert_eq!(
        object.read_property(P::ACCESS_DOORS, None).unwrap(),
        PropertyValue::List(vec![])
    );
    // READY until the application reports otherwise, and before any event
    // the no-credential reference: Access Credential 4194303 under [1].
    assert_eq!(
        object
            .read_property(P::AUTHENTICATION_STATUS, None)
            .unwrap(),
        PropertyValue::Enumerated(1)
    );
    assert_eq!(
        object
            .read_property(P::ACCESS_EVENT_CREDENTIAL, None)
            .unwrap(),
        PropertyValue::ApplicationData(vec![0x1C, 0x08, 0x3F, 0xFF, 0xFF])
    );
    // Access_Event_Time is one BACnetTimeStamp, so an index is rejected;
    // Access_Doors is a BACnetARRAY and takes one (#1169).
    assert!(object.is_array_property(P::ACCESS_DOORS));
    assert!(!object.is_array_property(P::ACCESS_EVENT_TIME));
    assert!(!object.is_array_property(P::ACCESS_EVENT_CREDENTIAL));
}

#[test]
fn property_metadata_access_zone_exact_sets_readable_rows_and_indexed_list() {
    let object = AccessZoneObject::new(1, "ZONE-1").unwrap();
    let all = [
        P::OBJECT_IDENTIFIER,
        P::OBJECT_NAME,
        P::DESCRIPTION,
        P::OBJECT_TYPE,
        P::GLOBAL_IDENTIFIER,
        P::OCCUPANCY_COUNT,
        P::ENTRY_POINTS,
        P::EXIT_POINTS,
        P::STATUS_FLAGS,
        P::OUT_OF_SERVICE,
        P::RELIABILITY,
        // The Table 12-37 rows #1284 added.
        P::OCCUPANCY_STATE,
        P::EVENT_STATE,
        P::OCCUPANCY_COUNT_ENABLE,
        P::ADJUST_VALUE,
        P::OCCUPANCY_UPPER_LIMIT,
        P::OCCUPANCY_LOWER_LIMIT,
    ]
    .into_iter()
    .chain(ZONE_EVENT_ROWS)
    .collect::<Vec<_>>();
    let required = [
        P::OBJECT_IDENTIFIER,
        P::OBJECT_NAME,
        P::OBJECT_TYPE,
        P::GLOBAL_IDENTIFIER,
        P::ENTRY_POINTS,
        P::EXIT_POINTS,
        P::STATUS_FLAGS,
        P::OUT_OF_SERVICE,
        P::RELIABILITY,
        P::OCCUPANCY_STATE,
        P::EVENT_STATE,
        P::PROPERTY_LIST,
    ];
    assert_exact_sets(&object, &all, &required);
    assert_indexed_property_list(&object, &all);
    assert!(!object.supports_cov());
    // Table 12-37 has neither of these rows (#1064).
    for property in [P::PRESENT_VALUE, P::ACCESS_DOORS] {
        assert_error(
            object.read_property(property, None).unwrap_err(),
            ErrorCode::UNKNOWN_PROPERTY,
        );
    }
    assert_eq!(
        object.read_property(P::GLOBAL_IDENTIFIER, None).unwrap(),
        PropertyValue::Unsigned(0)
    );
    // A new zone counts, from zero, with no limits and nothing adjusted, so
    // Occupancy_State is NORMAL and Event_State NORMAL.
    for (p, value) in [
        (P::OCCUPANCY_COUNT, PropertyValue::Unsigned(0)),
        (P::OCCUPANCY_STATE, PropertyValue::Enumerated(0)),
        (P::EVENT_STATE, PropertyValue::Enumerated(0)),
        (P::OCCUPANCY_COUNT_ENABLE, PropertyValue::Boolean(true)),
        (P::ADJUST_VALUE, PropertyValue::Signed(0)),
        (P::OCCUPANCY_UPPER_LIMIT, PropertyValue::Unsigned(0)),
        (P::OCCUPANCY_LOWER_LIMIT, PropertyValue::Unsigned(0)),
    ] {
        assert_eq!(object.read_property(p, None).unwrap(), value, "{p:?}");
        assert!(!object.is_array_property(p));
    }
    for p in [P::ENTRY_POINTS, P::EXIT_POINTS] {
        assert_eq!(
            object.read_property(p, None).unwrap(),
            PropertyValue::List(vec![])
        );
        assert!(!object.is_array_property(p));
    }
}

#[test]
fn property_metadata_access_trio_write_capabilities_match_dispatch() {
    // Constructor paired with the properties it must always accept writes
    // for, and those it must accept only while Out_Of_Service is TRUE.
    type WriteCase = (fn() -> Box<dyn BACnetObject>, &'static [P], &'static [P]);
    let cases: [WriteCase; 3] = [
        (
            || Box::new(AccessDoorObject::new(1, "DOOR-1").unwrap()),
            &[
                P::DESCRIPTION,
                P::OUT_OF_SERVICE,
                P::PRESENT_VALUE,
                P::RELINQUISH_DEFAULT,
                P::DOOR_PULSE_TIME,
                P::DOOR_EXTENDED_PULSE_TIME,
                P::DOOR_OPEN_TOO_LONG_TIME,
            ],
            // Table 12-30 footnote 1 (#1131).
            &[P::DOOR_STATUS, P::LOCK_STATUS, P::DOOR_ALARM_STATE],
        ),
        (
            || Box::new(AccessPointObject::new(1, "AP-1").unwrap()),
            // The policy in effect and the mode (#1307).
            &[
                P::DESCRIPTION,
                P::OUT_OF_SERVICE,
                P::ACTIVE_AUTHENTICATION_POLICY,
                P::AUTHORIZATION_MODE,
            ],
            &[],
        ),
        (
            || Box::new(AccessZoneObject::new(1, "ZONE-1").unwrap()),
            // Adjust_Value: Table 12-37 footnote 5 (#1284); the event
            // configuration (#1305).
            &[
                P::DESCRIPTION,
                P::OUT_OF_SERVICE,
                P::GLOBAL_IDENTIFIER,
                P::ADJUST_VALUE,
                P::TIME_DELAY,
                P::NOTIFICATION_CLASS,
                P::ALARM_VALUES,
                P::EVENT_ENABLE,
                P::NOTIFY_TYPE,
                P::EVENT_DETECTION_ENABLE,
                P::TIME_DELAY_NORMAL,
            ],
            // Table 12-37 footnote 1 (#1247).
            &[P::OCCUPANCY_COUNT, P::RELIABILITY],
        ),
    ];
    for (make, writable, when_out_of_service) in cases {
        for out_of_service in [false, true] {
            let mut object = make();
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
                let capability = if writable.contains(&p) {
                    PropertyWriteCapability::Always
                } else if when_out_of_service.contains(&p) {
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
            // Object_Name has no network write route: a rename falls
            // through to WRITE_ACCESS_DENIED even with a well-formed value.
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
}

#[test]
fn property_metadata_access_door_writes_command_priority_and_gate_relinquish() {
    for out_of_service in [false, true] {
        let mut object = AccessDoorObject::new(1, "DOOR-1").unwrap();
        object
            .write_property(
                P::OUT_OF_SERVICE,
                None,
                PropertyValue::Boolean(out_of_service),
                None,
            )
            .unwrap();
        // A priority write commands Present_Value; relinquishing the slot
        // falls back to Relinquish_Default.
        object
            .write_property(
                P::PRESENT_VALUE,
                None,
                PropertyValue::Enumerated(1),
                Some(8),
            )
            .unwrap();
        assert_eq!(
            object.read_property(P::PRESENT_VALUE, None).unwrap(),
            PropertyValue::Enumerated(1)
        );
        assert_eq!(
            object.read_property(P::PRIORITY_ARRAY, Some(8)).unwrap(),
            PropertyValue::Enumerated(1)
        );
        object
            .write_property(P::PRESENT_VALUE, None, PropertyValue::Null, Some(8))
            .unwrap();
        assert_eq!(
            object.read_property(P::PRESENT_VALUE, None).unwrap(),
            PropertyValue::Enumerated(0)
        );
        // Relinquish_Default admits LOCK and UNLOCK (Clause 12.26.11)
        // and resolves Present_Value anew from the empty array.
        for raw in [0u32, 1] {
            object
                .write_property(
                    P::RELINQUISH_DEFAULT,
                    None,
                    PropertyValue::Enumerated(raw),
                    None,
                )
                .unwrap();
            assert_eq!(
                object.read_property(P::RELINQUISH_DEFAULT, None).unwrap(),
                PropertyValue::Enumerated(raw)
            );
            assert_eq!(
                object.read_property(P::PRESENT_VALUE, None).unwrap(),
                PropertyValue::Enumerated(raw)
            );
        }
        object
            .write_property(
                P::RELINQUISH_DEFAULT,
                None,
                PropertyValue::Enumerated(1),
                None,
            )
            .unwrap();
        for raw in [2, 3, 4] {
            assert_error(
                object
                    .write_property(
                        P::RELINQUISH_DEFAULT,
                        None,
                        PropertyValue::Enumerated(raw),
                        None,
                    )
                    .unwrap_err(),
                ErrorCode::VALUE_OUT_OF_RANGE,
            );
        }
        assert_eq!(
            object.read_property(P::RELINQUISH_DEFAULT, None).unwrap(),
            PropertyValue::Enumerated(1)
        );
        // Mistyped values are rejected without changing state.
        for (p, value) in [
            (P::PRESENT_VALUE, PropertyValue::Real(1.0)),
            (P::RELINQUISH_DEFAULT, PropertyValue::Real(1.0)),
            (P::DOOR_PULSE_TIME, PropertyValue::Real(1.0)),
            (P::DESCRIPTION, PropertyValue::Unsigned(1)),
            (P::OUT_OF_SERVICE, PropertyValue::Unsigned(1)),
        ] {
            assert_error(
                object.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::INVALID_DATA_TYPE,
            );
        }
        assert_eq!(
            object.read_property(P::PRESENT_VALUE, None).unwrap(),
            PropertyValue::Enumerated(1)
        );
        // The footnote-1 status rows take their own readback only while
        // out of service (#1131).
        for p in [P::DOOR_STATUS, P::LOCK_STATUS, P::DOOR_ALARM_STATE] {
            let value = object.read_property(p, None).unwrap();
            let result = object.write_property(p, None, value, None);
            if out_of_service {
                result.unwrap();
            } else {
                assert_error(result.unwrap_err(), ErrorCode::WRITE_ACCESS_DENIED);
            }
            assert!(object.is_writable_property(p));
        }
        // The other Table-O status rows and the readable-only rows deny
        // even their own readback on write.
        for p in [
            P::SECURED_STATUS,
            P::DOOR_MEMBERS,
            P::PRIORITY_ARRAY,
            P::EVENT_STATE,
            P::STATUS_FLAGS,
            P::RELIABILITY,
            P::CURRENT_COMMAND_PRIORITY,
        ] {
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
fn property_metadata_access_point_and_zone_writes_store_verbatim() {
    for out_of_service in [false, true] {
        let mut point = AccessPointObject::new(1, "AP-1").unwrap();
        point
            .write_property(
                P::OUT_OF_SERVICE,
                None,
                PropertyValue::Boolean(out_of_service),
                None,
            )
            .unwrap();
        for p in [
            P::ACCESS_EVENT,
            P::ACCESS_EVENT_TAG,
            P::ACCESS_EVENT_TIME,
            P::ACCESS_DOORS,
            P::EVENT_STATE,
            P::STATUS_FLAGS,
            P::RELIABILITY,
            P::AUTHENTICATION_STATUS,
            P::ACCESS_EVENT_CREDENTIAL,
            P::NUMBER_OF_AUTHENTICATION_POLICIES,
            P::PRIORITY_FOR_WRITING,
        ] {
            let value = point.read_property(p, None).unwrap();
            assert_error(
                point.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::WRITE_ACCESS_DENIED,
            );
            assert!(!point.is_writable_property(p));
        }
        let mut zone = AccessZoneObject::new(1, "ZONE-1").unwrap();
        zone.write_property(
            P::OUT_OF_SERVICE,
            None,
            PropertyValue::Boolean(out_of_service),
            None,
        )
        .unwrap();
        zone.write_property(
            P::GLOBAL_IDENTIFIER,
            None,
            PropertyValue::Unsigned(99),
            None,
        )
        .unwrap();
        assert_eq!(
            zone.read_property(P::GLOBAL_IDENTIFIER, None).unwrap(),
            PropertyValue::Unsigned(99)
        );
        for (p, value) in [
            (P::GLOBAL_IDENTIFIER, PropertyValue::Enumerated(99)),
            (P::DESCRIPTION, PropertyValue::Unsigned(1)),
            (P::OUT_OF_SERVICE, PropertyValue::Unsigned(1)),
        ] {
            assert_error(
                zone.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::INVALID_DATA_TYPE,
            );
        }
        assert_eq!(
            zone.read_property(P::GLOBAL_IDENTIFIER, None).unwrap(),
            PropertyValue::Unsigned(99)
        );
        // The footnote-1 rows take their own readback only while out of
        // service (#1247).
        for p in [P::OCCUPANCY_COUNT, P::RELIABILITY] {
            let value = zone.read_property(p, None).unwrap();
            let result = zone.write_property(p, None, value, None);
            if out_of_service {
                result.unwrap();
            } else {
                assert_error(result.unwrap_err(), ErrorCode::WRITE_ACCESS_DENIED);
            }
            assert!(zone.is_writable_property(p));
        }
        for p in [
            P::ENTRY_POINTS,
            P::EXIT_POINTS,
            P::STATUS_FLAGS,
            P::OCCUPANCY_STATE,
            P::EVENT_STATE,
            P::OCCUPANCY_COUNT_ENABLE,
            P::OCCUPANCY_UPPER_LIMIT,
            P::OCCUPANCY_LOWER_LIMIT,
            P::ACKED_TRANSITIONS,
            P::EVENT_TIME_STAMPS,
            P::EVENT_MESSAGE_TEXTS,
        ] {
            let value = zone.read_property(p, None).unwrap();
            assert_error(
                zone.write_property(p, None, value, None).unwrap_err(),
                ErrorCode::WRITE_ACCESS_DENIED,
            );
            assert!(!zone.is_writable_property(p));
        }
    }
}

#[test]
fn property_metadata_access_trio_unserved_rows_stay_unknown() {
    fn assert_unserved(object: &mut dyn BACnetObject, p: P) {
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

    // Door_Unlock_Delay_Time and Masked_Alarm_Values are Table 12-30 O
    // rows with no read arm.
    let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
    assert_unserved(&mut door, P::DOOR_UNLOCK_DELAY_TIME);
    assert_unserved(&mut door, P::MASKED_ALARM_VALUES);
    // Access_Event_Authentication_Factor is a Table 12-36 O row with no read
    // arm; Present_Value is no Table 12-36 row (#1064). Authentication_Status
    // is served (#1284).
    let mut point = AccessPointObject::new(1, "AP-1").unwrap();
    assert_unserved(&mut point, P::ACCESS_EVENT_AUTHENTICATION_FACTOR);
    assert_unserved(&mut point, P::PRESENT_VALUE);
    // Credentials_In_Zone is a Table 12-37 O row with no read arm;
    // Present_Value and Access_Doors are no Table 12-37 rows (#1064).
    // Occupancy_State is served (#1284).
    let mut zone = AccessZoneObject::new(1, "ZONE-1").unwrap();
    assert_unserved(&mut zone, P::CREDENTIALS_IN_ZONE);
    assert_unserved(&mut zone, P::PRESENT_VALUE);
    assert_unserved(&mut zone, P::ACCESS_DOORS);
}
