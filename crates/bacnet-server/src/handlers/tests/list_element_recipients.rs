//! AddListElement and RemoveListElement on Notification Class Recipient_List,
//! the framed BACnetLIST of BACnetDestination (#152 review, #1027). The
//! property description does not narrow what makes two destinations the same,
//! so whole destinations compare: one that differs in any field, a process
//! identifier or a transition bit, is another element.

use super::*;
use bacnet_objects::notification_class::NotificationClass;
use bacnet_services::list_manipulation::ListElementRequest;
use bacnet_types::bitstring::{DaysOfWeek, EventTransitionBits};
use bacnet_types::constructed::{BACnetDestination, BACnetRecipient};
use bacnet_types::primitives::Time;

fn destination(device_instance: u32) -> BACnetDestination {
    let t = |hour, minute| Time {
        hour,
        minute,
        second: 0,
        hundredths: 0,
    };
    BACnetDestination {
        valid_days: DaysOfWeek::all(),
        from_time: t(0, 0),
        to_time: t(23, 59),
        recipient: BACnetRecipient::Device(
            ObjectIdentifier::new(ObjectType::DEVICE, device_instance).unwrap(),
        ),
        process_identifier: device_instance,
        issue_confirmed_notifications: false,
        transitions: EventTransitionBits::all(),
    }
}

fn framed(destinations: &[BACnetDestination]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    bacnet_encoding::constructed::encode_destination_list(&mut buf, destinations);
    buf.to_vec()
}

fn nc_db(entries: &[BACnetDestination]) -> (ObjectDatabase, ObjectIdentifier) {
    let mut db = ObjectDatabase::new();
    let mut nc = NotificationClass::new(1, "NC-1").unwrap();
    for entry in entries {
        nc.add_destination(entry.clone()).unwrap();
    }
    let oid = nc.object_identifier();
    db.add(Box::new(nc)).unwrap();
    (db, oid)
}

fn edit(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    list_of_elements: Vec<u8>,
    remove: bool,
) -> Result<(), Error> {
    let mut buf = BytesMut::new();
    ListElementRequest {
        object_identifier: oid,
        property_identifier: PropertyIdentifier::RECIPIENT_LIST,
        property_array_index: None,
        list_of_elements,
    }
    .encode(&mut buf)
    .unwrap();
    if remove {
        handle_remove_list_element(db, &buf)
    } else {
        handle_add_list_element(db, &buf)
    }
}

fn recipient_list_wire_bytes(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<u8> {
    let PropertyValue::ApplicationData(bytes) = db
        .get(&oid)
        .unwrap()
        .read_property(PropertyIdentifier::RECIPIENT_LIST, None)
        .unwrap()
    else {
        panic!("expected ApplicationData");
    };
    bytes
}

fn device_instances(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<u32> {
    bacnet_encoding::constructed::decode_destination_list(&recipient_list_wire_bytes(db, oid))
        .unwrap()
        .iter()
        .map(|d| match &d.recipient {
            BACnetRecipient::Device(o) => o.instance_number(),
            other => panic!("expected Device recipient, got {other:?}"),
        })
        .collect()
}

#[test]
fn remove_list_element_from_framed_recipient_list_leaves_rest() {
    let (mut db, oid) = nc_db(&[destination(10), destination(20), destination(30)]);
    edit(&mut db, oid, framed(&[destination(20)]), true).unwrap();
    assert_eq!(device_instances(&db, oid), vec![10, 30]);
    // The wire form re-encodes as exactly the two remaining destinations.
    assert_eq!(
        recipient_list_wire_bytes(&db, oid),
        framed(&[destination(10), destination(30)])
    );
}

#[test]
fn remove_list_element_absent_recipient_fails_and_removes_nothing() {
    let (mut db, oid) = nc_db(&[destination(10), destination(20)]);
    let before = recipient_list_wire_bytes(&db, oid);
    // 20 is present, 99 is not: the request fails at 99 and 20 stays.
    for (elements, position) in [
        (vec![destination(99)], 1),
        (vec![destination(20), destination(99)], 2),
    ] {
        assert_eq!(
            list_refusal(edit(&mut db, oid, framed(&elements), true)),
            (
                ErrorClass::SERVICES,
                ErrorCode::LIST_ELEMENT_NOT_FOUND,
                position
            )
        );
        assert_eq!(
            recipient_list_wire_bytes(&db, oid),
            before,
            "bytes unchanged"
        );
    }
}

#[test]
fn recipient_list_elements_compare_as_whole_destinations() {
    let (mut db, oid) = nc_db(&[destination(10)]);
    let mut other_process = destination(10);
    other_process.process_identifier = 11;
    let mut fewer_transitions = destination(10);
    fewer_transitions.transitions =
        EventTransitionBits::TO_OFFNORMAL | EventTransitionBits::TO_FAULT;
    // Same recipient, other fields: neither is the stored element.
    for variant in [&other_process, &fewer_transitions] {
        assert_eq!(
            list_refusal(edit(
                &mut db,
                oid,
                framed(std::slice::from_ref(variant)),
                true
            )),
            (ErrorClass::SERVICES, ErrorCode::LIST_ELEMENT_NOT_FOUND, 1)
        );
    }
    // So adding them appends them, while the identical destination is left.
    edit(
        &mut db,
        oid,
        framed(&[
            destination(10),
            other_process.clone(),
            other_process.clone(),
        ]),
        false,
    )
    .unwrap();
    assert_eq!(
        recipient_list_wire_bytes(&db, oid),
        framed(&[destination(10), other_process])
    );
}

#[test]
fn add_list_element_to_framed_recipient_list_appends() {
    let (mut db, oid) = nc_db(&[destination(10)]);
    edit(
        &mut db,
        oid,
        framed(&[destination(20), destination(30)]),
        false,
    )
    .unwrap();
    assert_eq!(device_instances(&db, oid), vec![10, 20, 30]);
    assert_eq!(
        recipient_list_wire_bytes(&db, oid),
        framed(&[destination(10), destination(20), destination(30)])
    );
    // Adding a present destination again leaves the list as it is.
    edit(&mut db, oid, framed(&[destination(20)]), false).unwrap();
    assert_eq!(device_instances(&db, oid), vec![10, 20, 30]);
}

#[test]
fn remove_list_element_malformed_framed_payload_errors_and_preserves() {
    let (mut db, oid) = nc_db(&[destination(10), destination(20)]);
    let before = recipient_list_wire_bytes(&db, oid);
    // Well-formed TLV, but NOT a BACnetDestination (a bare application
    // Unsigned where the second destination's valid-days bit string belongs).
    let mut elements = framed(&[destination(10)]);
    elements.extend_from_slice(&[0x21, 0x2A]);
    for remove in [true, false] {
        assert_eq!(
            list_refusal(edit(&mut db, oid, elements.clone(), remove)),
            (ErrorClass::PROPERTY, ErrorCode::INVALID_DATA_TYPE, 2)
        );
        assert_eq!(
            recipient_list_wire_bytes(&db, oid),
            before,
            "no silent wipe"
        );
    }
}
