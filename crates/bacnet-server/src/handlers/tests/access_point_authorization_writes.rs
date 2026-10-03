//! Access Point Active_Authentication_Policy and Authorization_Mode over
//! WriteProperty and WritePropertyMultiple, and the read-only
//! Number_Of_Authentication_Policies and Priority_For_Writing (Clauses
//! 12.31.10, 12.31.11, 12.31.14 and 12.31.33; #1307).

use super::*;
use bacnet_objects::access_control::AccessPointObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::WriteAccessSpecification;
use PropertyIdentifier as P;

fn point_db() -> (ObjectDatabase, ObjectIdentifier) {
    let point = AccessPointObject::new(1, "AP-1").unwrap();
    let oid = point.object_identifier();
    let mut db = ObjectDatabase::new();
    db.add(Box::new(point)).unwrap();
    (db, oid)
}

fn encode(value: &PropertyValue) -> Vec<u8> {
    let mut buf = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut buf, value).unwrap();
    buf.to_vec()
}

fn write_property(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    property: P,
    index: Option<u32>,
    value: &PropertyValue,
) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: index,
        property_value: encode(value),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property(db, &request).map(|_| ())
}

fn write_property_multiple(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    writes: &[(P, PropertyValue)],
) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: oid,
            list_of_properties: writes
                .iter()
                .map(|(property, value)| BACnetPropertyValue {
                    property_identifier: *property,
                    property_array_index: None,
                    value: encode(value),
                    priority: None,
                })
                .collect(),
        }],
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property_multiple(db, &request).map(|_| ())
}

/// The ReadProperty-ACK value bytes of one property.
fn read_bytes(db: &ObjectDatabase, oid: ObjectIdentifier, property: P) -> Vec<u8> {
    let mut request = BytesMut::new();
    ReadPropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: None,
    }
    .encode(&mut request);
    let mut response = BytesMut::new();
    handle_read_property(db, &request, &mut response).unwrap();
    ReadPropertyACK::decode(&response).unwrap().property_value
}

/// Active_Authentication_Policy, Number_Of_Authentication_Policies,
/// Authorization_Mode and Priority_For_Writing as served.
fn served(db: &ObjectDatabase, oid: ObjectIdentifier) -> [Vec<u8>; 4] {
    [
        P::ACTIVE_AUTHENTICATION_POLICY,
        P::NUMBER_OF_AUTHENTICATION_POLICIES,
        P::AUTHORIZATION_MODE,
        P::PRIORITY_FOR_WRITING,
    ]
    .map(|property| read_bytes(db, oid, property))
}

fn assert_property_error(result: Result<(), Error>, expected: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class, code })
            if class == ErrorClass::PROPERTY.to_raw() as u32
                && code == expected.to_raw() as u32),
        "expected PROPERTY / {expected:?}, got {result:?}"
    );
}

#[test]
fn write_property_sets_the_access_point_policy_and_mode() {
    let (mut db, oid) = point_db();
    // One policy in effect, AUTHORIZE (0) and priority 16.
    assert_eq!(
        served(&db, oid),
        [vec![0x21, 1], vec![0x21, 1], vec![0x91, 0], vec![0x21, 16]]
    );
    write_property(
        &mut db,
        oid,
        P::ACTIVE_AUTHENTICATION_POLICY,
        None,
        &PropertyValue::Unsigned(1),
    )
    .unwrap();
    // DENY_ALL (2), then NONE (5).
    for (mode, wire) in [(2, 0x02), (5, 0x05)] {
        write_property(
            &mut db,
            oid,
            P::AUTHORIZATION_MODE,
            None,
            &PropertyValue::Enumerated(mode),
        )
        .unwrap();
        assert_eq!(
            read_bytes(&db, oid, P::AUTHORIZATION_MODE),
            vec![0x91, wire]
        );
    }
    // Both in one WritePropertyMultiple: GRANT_ACTIVE (1).
    write_property_multiple(
        &mut db,
        oid,
        &[
            (P::ACTIVE_AUTHENTICATION_POLICY, PropertyValue::Unsigned(1)),
            (P::AUTHORIZATION_MODE, PropertyValue::Enumerated(1)),
        ],
    )
    .unwrap();
    assert_eq!(
        served(&db, oid),
        [vec![0x21, 1], vec![0x21, 1], vec![0x91, 1], vec![0x21, 16]]
    );
}

#[test]
fn write_property_refuses_other_policy_mode_and_read_only_writes() {
    let (mut db, oid) = point_db();
    let unchanged = served(&db, oid);
    let refusals = [
        // Zero and 2 name no policy of the one the point defines.
        (
            P::ACTIVE_AUTHENTICATION_POLICY,
            None,
            PropertyValue::Unsigned(0),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
        (
            P::ACTIVE_AUTHENTICATION_POLICY,
            None,
            PropertyValue::Unsigned(2),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
        (
            P::ACTIVE_AUTHENTICATION_POLICY,
            None,
            PropertyValue::Enumerated(1),
            ErrorCode::INVALID_DATA_TYPE,
        ),
        // A reserved mode and an undeclared proprietary one.
        (
            P::AUTHORIZATION_MODE,
            None,
            PropertyValue::Enumerated(6),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
        (
            P::AUTHORIZATION_MODE,
            None,
            PropertyValue::Enumerated(64),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
        (
            P::AUTHORIZATION_MODE,
            None,
            PropertyValue::Unsigned(2),
            ErrorCode::INVALID_DATA_TYPE,
        ),
        (
            P::AUTHORIZATION_MODE,
            Some(1),
            PropertyValue::Enumerated(2),
            ErrorCode::PROPERTY_IS_NOT_AN_ARRAY,
        ),
        // The application's rows.
        (
            P::NUMBER_OF_AUTHENTICATION_POLICIES,
            None,
            PropertyValue::Unsigned(2),
            ErrorCode::WRITE_ACCESS_DENIED,
        ),
        (
            P::PRIORITY_FOR_WRITING,
            None,
            PropertyValue::Unsigned(8),
            ErrorCode::WRITE_ACCESS_DENIED,
        ),
    ];
    for (property, index, value, expected) in refusals {
        assert_property_error(
            write_property(&mut db, oid, property, index, &value),
            expected,
        );
        assert_eq!(served(&db, oid), unchanged, "{property:?}");
    }

    // WritePropertyMultiple stops at the refused mode; the mode written
    // before it stands.
    write_property_multiple(
        &mut db,
        oid,
        &[(P::AUTHORIZATION_MODE, PropertyValue::Enumerated(2))],
    )
    .unwrap();
    assert_property_error(
        write_property_multiple(
            &mut db,
            oid,
            &[
                (P::AUTHORIZATION_MODE, PropertyValue::Enumerated(0)),
                (P::AUTHORIZATION_MODE, PropertyValue::Enumerated(65_536)),
            ],
        ),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_eq!(read_bytes(&db, oid, P::AUTHORIZATION_MODE), vec![0x91, 0]);
}
