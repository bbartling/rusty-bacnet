//! Elevator Group and Lift properties over WriteProperty and ReadProperty:
//! the Elevator Group's Table 12-76 property set (#997) and the Lift's
//! Car_Moving_Direction domain (#998).

use super::*;
use bacnet_objects::elevator::{ElevatorGroupObject, LiftObject};
use bacnet_types::enums::LiftCarDirection;

fn db_with(object: Box<dyn BACnetObject>) -> (ObjectDatabase, ObjectIdentifier) {
    let oid = object.object_identifier();
    let mut db = ObjectDatabase::new();
    db.add(object).unwrap();
    (db, oid)
}

fn write(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Result<(), Error> {
    let mut property_value = BytesMut::new();
    encode_property_value(&mut property_value, &value).unwrap();
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: None,
        property_value: property_value.to_vec(),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property(db, &request).map(|_| ())
}

/// The raw propertyValue a ReadProperty ACK carries.
fn read_wire(db: &ObjectDatabase, oid: ObjectIdentifier, property: PropertyIdentifier) -> Vec<u8> {
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

fn assert_property_error(result: Result<(), Error>, expected: ErrorCode, context: &str) {
    assert!(
        matches!(result, Err(Error::Protocol { class, code })
            if class == ErrorClass::PROPERTY.to_raw() as u32
                && code == expected.to_raw() as u32),
        "{context}: expected PROPERTY/{expected:?}, got {result:?}"
    );
}

#[test]
fn wp_elevator_group_properties_outside_table_12_76_are_unknown() {
    let (mut db, oid) = db_with(Box::new(ElevatorGroupObject::new(1, "EG-1").unwrap()));
    let before = read_wire(&db, oid, PropertyIdentifier::PROPERTY_LIST);
    for (property, value) in [
        (
            PropertyIdentifier::STATUS_FLAGS,
            PropertyValue::BitString {
                unused_bits: 4,
                data: vec![0],
            },
        ),
        (
            PropertyIdentifier::OUT_OF_SERVICE,
            PropertyValue::Boolean(true),
        ),
        (
            PropertyIdentifier::OUT_OF_SERVICE,
            PropertyValue::Boolean(false),
        ),
        (
            PropertyIdentifier::RELIABILITY,
            PropertyValue::Enumerated(0),
        ),
    ] {
        assert_property_error(
            write(&mut db, oid, property, value),
            ErrorCode::UNKNOWN_PROPERTY,
            &format!("{property:?}"),
        );
    }
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::PROPERTY_LIST),
        before
    );
}

#[test]
fn wp_elevator_group_machine_room_id_reads_but_refuses_writes() {
    let (mut db, oid) = db_with(Box::new(ElevatorGroupObject::new(1, "EG-1").unwrap()));
    // Positive Integer Value (type 48), instance 4194303: no machine room number.
    let none = [0xC4, 0x0C, 0x3F, 0xFF, 0xFF];
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::MACHINE_ROOM_ID),
        none
    );
    let piv = ObjectIdentifier::new(ObjectType::POSITIVE_INTEGER_VALUE, 9).unwrap();
    assert_property_error(
        write(
            &mut db,
            oid,
            PropertyIdentifier::MACHINE_ROOM_ID,
            PropertyValue::ObjectIdentifier(piv),
        ),
        ErrorCode::WRITE_ACCESS_DENIED,
        "Machine_Room_ID write",
    );
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::MACHINE_ROOM_ID),
        none
    );
}

#[test]
fn wp_elevator_group_group_id_holds_to_unsigned8() {
    let (mut db, oid) = db_with(Box::new(ElevatorGroupObject::new(1, "EG-1").unwrap()));
    write(
        &mut db,
        oid,
        PropertyIdentifier::GROUP_ID,
        PropertyValue::Unsigned(255),
    )
    .unwrap();
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::GROUP_ID),
        [0x21, 0xFF]
    );
    for raw in [256u64, 70_000, u64::from(u32::MAX)] {
        assert_property_error(
            write(
                &mut db,
                oid,
                PropertyIdentifier::GROUP_ID,
                PropertyValue::Unsigned(raw),
            ),
            ErrorCode::VALUE_OUT_OF_RANGE,
            &format!("Group_ID {raw}"),
        );
        assert_eq!(
            read_wire(&db, oid, PropertyIdentifier::GROUP_ID),
            [0x21, 0xFF]
        );
    }
}

#[test]
fn wp_lift_car_moving_direction_accepts_the_bacnet_lift_car_direction_domain() {
    let (mut db, oid) = db_with(Box::new(LiftObject::new(1, "LIFT-1", 3).unwrap()));
    let cmd = PropertyIdentifier::CAR_MOVING_DIRECTION;
    // A fresh lift reads STOPPED (2).
    assert_eq!(read_wire(&db, oid, cmd), [0x91, 0x02]);
    for (raw, wire) in [
        (LiftCarDirection::DOWN.to_raw(), &[0x91, 0x04][..]),
        (LiftCarDirection::UP_AND_DOWN.to_raw(), &[0x91, 0x05]),
        (1024, &[0x92, 0x04, 0x00]),
        (65_535, &[0x92, 0xFF, 0xFF]),
    ] {
        write(&mut db, oid, cmd, PropertyValue::Enumerated(raw))
            .unwrap_or_else(|e| panic!("Car_Moving_Direction {raw} must be accepted: {e:?}"));
        assert_eq!(read_wire(&db, oid, cmd), wire, "{raw}");
    }
    for raw in [6u32, 1023, 65_536, u32::MAX] {
        assert_property_error(
            write(&mut db, oid, cmd, PropertyValue::Enumerated(raw)),
            ErrorCode::VALUE_OUT_OF_RANGE,
            &format!("Car_Moving_Direction {raw}"),
        );
        assert_eq!(read_wire(&db, oid, cmd), [0x92, 0xFF, 0xFF], "{raw}");
    }
}
