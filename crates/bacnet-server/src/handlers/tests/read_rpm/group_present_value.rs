//! Group (type 11) Present_Value rebuilt from List_Of_Group_Members on each
//! read (#1134), through ReadProperty, both ReadPropertyMultiple builders
//! and ReadRange.

use super::group::{assert_cases, ExpectedRead};
use super::*;
use bacnet_objects::analog::{AnalogInputObject, AnalogValueObject};
use bacnet_objects::group::GroupObject;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::read_range::{RangeSpec, ReadRangeAck, ReadRangeRequest};
use bacnet_types::constructed::{PropertyReference, ReadAccessSpecification};
use bacnet_types::primitives::PropertyValue;
use PropertyIdentifier as P;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn member(
    object_identifier: ObjectIdentifier,
    references: &[(P, Option<u32>)],
) -> ReadAccessSpecification {
    ReadAccessSpecification {
        object_identifier,
        list_of_property_references: references
            .iter()
            .map(
                |&(property_identifier, property_array_index)| PropertyReference {
                    property_identifier,
                    property_array_index,
                },
            )
            .collect(),
    }
}

/// AI-1 reading 21.5, AV-2 with an empty priority array, and Group 7 over
/// them with the members below. AI-9 is not in the database.
fn database(members: Vec<ReadAccessSpecification>) -> (ObjectDatabase, ObjectIdentifier) {
    let mut input = AnalogInputObject::new(1, "AI-1", 62).unwrap();
    input.set_present_value(21.5);
    let mut group = GroupObject::new(7, "GRP-7").unwrap();
    for member in members {
        group.add_member(member).unwrap();
    }
    let group_oid = group.object_identifier();
    let mut db = ObjectDatabase::new();
    db.add(Box::new(input)).unwrap();
    db.add(Box::new(AnalogValueObject::new(2, "AV-2", 62).unwrap()))
        .unwrap();
    db.add(Box::new(group)).unwrap();
    (db, group_oid)
}

fn pinned_members() -> Vec<ReadAccessSpecification> {
    vec![
        member(
            oid(ObjectType::ANALOG_INPUT, 1),
            &[(P::PRESENT_VALUE, None), (P::STATUS_FLAGS, None)],
        ),
        member(
            oid(ObjectType::ANALOG_INPUT, 1),
            &[(P::PRIORITY_ARRAY, None)],
        ),
        member(
            oid(ObjectType::ANALOG_INPUT, 9),
            &[(P::PRESENT_VALUE, None)],
        ),
        member(
            oid(ObjectType::ANALOG_VALUE, 2),
            &[(P::PRIORITY_ARRAY, Some(16))],
        ),
        member(
            oid(ObjectType::ANALOG_INPUT, 1),
            &[(P::PRESENT_VALUE, Some(1))],
        ),
    ]
}

// The pinned members, written out from the Clause 21 tags. Each
// ReadAccessSpecification is the object in [0] and its references inside
// [1]; each ReadAccessResult is the object in [0], then inside [1] each
// property in [2], an array index in [3] where one applies, and the value
// framed in [4] or the error class and code framed in [5].
const MEMBERS: &[u8] = &[
    0x0C, 0, 0, 0, 1, 0x1E, 0x09, 85, 0x09, 111, 0x1F, // AI-1 PV, Status_Flags
    0x0C, 0, 0, 0, 1, 0x1E, 0x09, 87, 0x1F, // AI-1 Priority_Array
    0x0C, 0, 0, 0, 9, 0x1E, 0x09, 85, 0x1F, // AI-9 PV
    0x0C, 0, 0x80, 0, 2, 0x1E, 0x09, 87, 0x19, 16, 0x1F, // AV-2 Priority_Array[16]
    0x0C, 0, 0, 0, 1, 0x1E, 0x09, 85, 0x19, 1, 0x1F, // AI-1 PV[1]
];
const PRESENT_VALUE: &[u8] = &[
    0x0C, 0, 0, 0, 1, 0x1E, // AI-1:
    0x29, 85, 0x4E, 0x44, 0x41, 0xAC, 0, 0, 0x4F, // Present_Value REAL 21.5,
    0x29, 111, 0x4E, 0x82, 4, 0, 0x4F, 0x1F, // Status_Flags all clear.
    0x0C, 0, 0, 0, 1, 0x1E, // AI-1 has no Priority_Array:
    0x29, 87, 0x5E, 0x91, 2, 0x91, 32, 0x5F, 0x1F, // PROPERTY / UNKNOWN_PROPERTY.
    0x0C, 0, 0, 0, 9, 0x1E, // AI-9 isn't here:
    0x29, 85, 0x5E, 0x91, 1, 0x91, 31, 0x5F, 0x1F, // OBJECT / UNKNOWN_OBJECT.
    0x0C, 0, 0x80, 0, 2, 0x1E, // AV-2 slot 16, the index echoed:
    0x29, 87, 0x39, 16, 0x4E, 0x00, 0x4F, 0x1F, // NULL.
    0x0C, 0, 0, 0, 1, 0x1E, // An index on AI-1's scalar Present_Value:
    0x29, 85, 0x5E, 0x91, 2, 0x91, 50, 0x5F, 0x1F, // PROPERTY_IS_NOT_AN_ARRAY, no index.
];

#[test]
fn group_present_value_holds_one_read_access_result_per_member() {
    let (db, group) = database(pinned_members());
    let cases: &[(P, Option<u32>, ExpectedRead)] = &[
        (P::LIST_OF_GROUP_MEMBERS, None, Ok(MEMBERS)),
        (P::PRESENT_VALUE, None, Ok(PRESENT_VALUE)),
        (
            P::PRESENT_VALUE,
            Some(0),
            Err(ErrorCode::PROPERTY_IS_NOT_AN_ARRAY),
        ),
        (
            P::LIST_OF_GROUP_MEMBERS,
            Some(1),
            Err(ErrorCode::PROPERTY_IS_NOT_AN_ARRAY),
        ),
    ];
    assert_cases(&db, group, cases);
}

/// The ReadPropertyMultiple-ACK octets for one specification alone.
fn rpm_ack(db: &ObjectDatabase, spec: &ReadAccessSpecification) -> Vec<u8> {
    let mut request = BytesMut::new();
    ReadPropertyMultipleRequest {
        list_of_read_access_specs: vec![spec.clone()],
    }
    .encode(&mut request)
    .unwrap();
    let mut ack = BytesMut::new();
    handle_read_property_multiple(db, &request, &mut ack).unwrap();
    ack.to_vec()
}

fn group_present_value(db: &ObjectDatabase, group: ObjectIdentifier) -> Vec<Vec<u8>> {
    let mut request = BytesMut::new();
    ReadPropertyRequest {
        object_identifier: group,
        property_identifier: P::PRESENT_VALUE,
        property_array_index: None,
    }
    .encode(&mut request);
    let mut response = BytesMut::new();
    handle_read_property(db, &request, &mut response).unwrap();
    let value = ReadPropertyACK::decode(&response).unwrap().property_value;
    // Split the list back into elements, one ReadAccessResult each.
    ReadPropertyMultipleACK::decode(&value)
        .unwrap()
        .list_of_read_access_results
        .iter()
        .map(|result| {
            let mut encoded = BytesMut::new();
            result.encode(&mut encoded);
            encoded.to_vec()
        })
        .collect()
}

#[test]
fn each_member_reads_as_read_property_multiple_reads_its_specification() {
    // Selectors expand against the member, and the Device wildcard resolves
    // to this device, as they do in a ReadPropertyMultiple request.
    let device = bacnet_objects::device::DeviceObject::new(bacnet_objects::device::DeviceConfig {
        instance: 100,
        name: "DEV-100".into(),
        ..Default::default()
    })
    .unwrap();
    let members = vec![
        member(oid(ObjectType::ANALOG_INPUT, 1), &[(P::ALL, None)]),
        member(
            oid(ObjectType::ANALOG_VALUE, 2),
            &[(P::REQUIRED, None), (P::PRIORITY_ARRAY, Some(0))],
        ),
        member(oid(ObjectType::ANALOG_VALUE, 2), &[(P::OPTIONAL, None)]),
        member(oid(ObjectType::GROUP, 7), &[(P::OPTIONAL, None)]),
        member(oid(ObjectType::DEVICE, 4194303), &[(P::OBJECT_NAME, None)]),
        member(oid(ObjectType::ANALOG_INPUT, 9), &[(P::ALL, None)]),
    ];
    let (mut db, group) = database(members.clone());
    db.add(Box::new(device)).unwrap();
    let elements = group_present_value(&db, group);
    assert_eq!(elements.len(), members.len());
    for (element, spec) in elements.iter().zip(&members) {
        assert_eq!(element, &rpm_ack(&db, spec), "{spec:?}");
    }
    // The wildcard member reports the Device it resolved to.
    assert_eq!(elements[4][..5], [0x0C, 0x02, 0, 0, 100]);
}

#[test]
fn group_present_value_is_rebuilt_on_each_read() {
    let input = oid(ObjectType::ANALOG_INPUT, 1);
    let (mut db, group) = database(vec![member(input, &[(P::DESCRIPTION, None)])]);
    let before = group_present_value(&db, group);
    db.get_mut(&input)
        .unwrap()
        .write_property(
            P::DESCRIPTION,
            None,
            PropertyValue::CharacterString("hot".into()),
            None,
        )
        .unwrap();
    let after = group_present_value(&db, group);
    // DESCRIPTION is property 28; the value is an application-tagged
    // CharacterString, UTF-8 (character set 0).
    assert_eq!(
        before,
        [vec![
            0x0C, 0, 0, 0, 1, 0x1E, 0x29, 28, 0x4E, 0x71, 0, 0x4F, 0x1F
        ]]
    );
    assert_eq!(
        after,
        [vec![
            0x0C, 0, 0, 0, 1, 0x1E, 0x29, 28, 0x4E, 0x74, 0, b'h', b'o', b't', 0x4F, 0x1F,
        ]]
    );
}

#[test]
fn read_range_pages_the_rebuilt_present_value() {
    let (db, group) = database(pinned_members());
    let mut request = BytesMut::new();
    ReadRangeRequest {
        object_identifier: group,
        property_identifier: P::PRESENT_VALUE,
        property_array_index: None,
        range: Some(RangeSpec::ByPosition {
            reference_index: 2,
            count: 2,
        }),
    }
    .encode(&mut request)
    .unwrap();
    let mut response = BytesMut::new();
    handle_read_range(&db, &request, &mut response).unwrap();
    let ack = ReadRangeAck::decode(&response).unwrap();
    assert_eq!(ack.item_count, 2);
    assert_eq!(ack.result_flags, (false, false, false));
    // Items 2 and 3: the two error results.
    assert_eq!(ack.item_data, PRESENT_VALUE[23..53]);
}
