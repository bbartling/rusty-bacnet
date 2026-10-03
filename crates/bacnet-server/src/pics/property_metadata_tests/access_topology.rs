use super::*;
use bacnet_objects::access_control::{AccessDoorObject, AccessPointObject, AccessZoneObject};
use bacnet_types::primitives::PropertyValue;
use PropertyIdentifier as P;

fn expected_rows(kind: ObjectType) -> Vec<PropertyRow> {
    // Independent (identifier, optional, writable) rows in declaration order; PICS sorts by property ID.
    match kind {
        ObjectType::ACCESS_DOOR => vec![
            (P::OBJECT_IDENTIFIER, false, false),
            (P::OBJECT_NAME, false, false),
            (P::DESCRIPTION, true, true),
            (P::OBJECT_TYPE, false, false),
            (P::PRESENT_VALUE, false, true),
            // Writable while Out_Of_Service is TRUE (Table 12-30 footnote 1).
            (P::DOOR_STATUS, true, true),
            (P::LOCK_STATUS, true, true),
            (P::SECURED_STATUS, true, false),
            (P::DOOR_ALARM_STATE, true, true),
            (P::DOOR_MEMBERS, true, false),
            (P::STATUS_FLAGS, false, false),
            (P::OUT_OF_SERVICE, false, true),
            (P::RELIABILITY, false, false),
            (P::EVENT_STATE, false, false),
            (P::PRIORITY_ARRAY, false, false),
            (P::RELINQUISH_DEFAULT, false, true),
            (P::DOOR_PULSE_TIME, false, true),
            (P::DOOR_EXTENDED_PULSE_TIME, false, true),
            (P::DOOR_OPEN_TOO_LONG_TIME, false, true),
            (P::CURRENT_COMMAND_PRIORITY, false, false),
            (P::PROPERTY_LIST, false, false),
        ],
        ObjectType::ACCESS_POINT => vec![
            (P::OBJECT_IDENTIFIER, false, false),
            (P::OBJECT_NAME, false, false),
            (P::DESCRIPTION, true, true),
            (P::OBJECT_TYPE, false, false),
            // Table 12-36 has no Present_Value row (#1064).
            (P::ACCESS_EVENT, false, false),
            (P::ACCESS_EVENT_TAG, false, false),
            (P::ACCESS_EVENT_TIME, false, false),
            (P::ACCESS_DOORS, false, false),
            (P::EVENT_STATE, false, false),
            (P::STATUS_FLAGS, false, false),
            (P::OUT_OF_SERVICE, false, true),
            (P::RELIABILITY, false, false),
            // The Table 12-36 required rows #1284 added.
            (P::AUTHENTICATION_STATUS, false, false),
            (P::ACCESS_EVENT_CREDENTIAL, false, false),
            (P::PROPERTY_LIST, false, false),
        ],
        _ => vec![
            (P::OBJECT_IDENTIFIER, false, false),
            (P::OBJECT_NAME, false, false),
            (P::DESCRIPTION, true, true),
            (P::OBJECT_TYPE, false, false),
            // Table 12-37 has no Present_Value or Access_Doors row (#1064).
            (P::GLOBAL_IDENTIFIER, false, true),
            // Writable while Out_Of_Service is TRUE (Table 12-37 footnote 1).
            (P::OCCUPANCY_COUNT, true, true),
            (P::ENTRY_POINTS, false, false),
            (P::EXIT_POINTS, false, false),
            (P::STATUS_FLAGS, false, false),
            (P::OUT_OF_SERVICE, false, true),
            (P::RELIABILITY, false, true),
            // The Table 12-37 rows #1284 added; Adjust_Value is writable
            // (footnote 5).
            (P::OCCUPANCY_STATE, false, false),
            (P::EVENT_STATE, false, false),
            (P::OCCUPANCY_COUNT_ENABLE, true, false),
            (P::ADJUST_VALUE, true, true),
            (P::OCCUPANCY_UPPER_LIMIT, true, false),
            (P::OCCUPANCY_LOWER_LIMIT, true, false),
            (P::PROPERTY_LIST, false, false),
        ],
    }
}

#[test]
fn pics_access_topology_property_metadata_is_exact() {
    let fresh: [FreshObject; 3] = [
        || {
            (
                Box::new(AccessDoorObject::new(7, "DOOR-7").unwrap()),
                ObjectType::ACCESS_DOOR,
            )
        },
        || {
            (
                Box::new(AccessPointObject::new(7, "AP-7").unwrap()),
                ObjectType::ACCESS_POINT,
            )
        },
        || {
            (
                Box::new(AccessZoneObject::new(7, "ZONE-7").unwrap()),
                ObjectType::ACCESS_ZONE,
            )
        },
    ];
    for make in fresh {
        let expected = expected_rows(make().1);
        for configured in [false, true] {
            for out_of_service in [false, true] {
                let (mut object, kind) = make();
                if configured {
                    object
                        .write_property(
                            P::DESCRIPTION,
                            None,
                            PropertyValue::CharacterString("long access label".repeat(100)),
                            None,
                        )
                        .unwrap();
                }
                object
                    .write_property(
                        P::OUT_OF_SERVICE,
                        None,
                        PropertyValue::Boolean(out_of_service),
                        None,
                    )
                    .unwrap();
                let required = object.required_properties();
                let mut db = ObjectDatabase::new();
                db.add(object).unwrap();
                let pics = generate_pics(&db, &ServerConfig::default(), &PicsConfig::default());
                assert_eq!(pics.supported_object_types.len(), 1);
                let support = &pics.supported_object_types[0];
                assert_eq!(support.object_type, kind);
                assert!(!support.createable);
                assert!(support.deleteable);
                let rows: Vec<_> = support
                    .supported_properties
                    .iter()
                    .map(|row| {
                        assert!(row.access.readable);
                        (row.property_id, row.access.optional, row.access.writable)
                    })
                    .collect();
                assert_eq!(
                    rows,
                    sorted_rows(&expected),
                    "{kind:?}, configured={configured}, OOS={out_of_service}"
                );
                assert_eq!(
                    rows.iter()
                        .filter_map(|&(p, optional, _)| (!optional).then_some(p))
                        .collect::<Vec<_>>(),
                    sorted_required(required.as_ref())
                );
            }
        }
    }
}
