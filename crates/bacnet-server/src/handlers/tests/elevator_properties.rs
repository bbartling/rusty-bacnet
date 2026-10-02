//! Elevator Group, Lift and Escalator properties over WriteProperty and
//! ReadProperty: the Elevator Group's Table 12-76 property set (#997), the
//! Lift's Car_Moving_Direction domain (#998), and the Lift and Escalator
//! Table 12-77 / 12-78 rows and datatypes (#1021, #1022).

use super::*;
use bacnet_objects::elevator::{ElevatorGroupObject, EscalatorObject, LiftObject};
use bacnet_types::enums::{LiftCarDirection, LiftFault};

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

#[test]
fn wp_lift_and_escalator_membership_rows_read_but_refuse_writes() {
    let objects: [Box<dyn BACnetObject>; 2] = [
        Box::new(LiftObject::new(1, "LIFT-1", 3).unwrap()),
        Box::new(EscalatorObject::new(1, "ESC-1").unwrap()),
    ];
    let group = ObjectIdentifier::new(ObjectType::ELEVATOR_GROUP, 5).unwrap();
    for object in objects {
        let (mut db, oid) = db_with(object);
        // Elevator Group (type 57) instance 4194303: no group lists it.
        for (property, wire, value) in [
            (
                PropertyIdentifier::ELEVATOR_GROUP,
                &[0xC4, 0x0E, 0x7F, 0xFF, 0xFF][..],
                PropertyValue::ObjectIdentifier(group),
            ),
            (
                PropertyIdentifier::GROUP_ID,
                &[0x21, 0x00],
                PropertyValue::Unsigned(3),
            ),
            (
                PropertyIdentifier::INSTALLATION_ID,
                &[0x21, 0x00],
                PropertyValue::Unsigned(3),
            ),
        ] {
            assert_eq!(read_wire(&db, oid, property), wire, "{oid:?} {property:?}");
            assert_property_error(
                write(&mut db, oid, property, value),
                ErrorCode::WRITE_ACCESS_DENIED,
                &format!("{oid:?} {property:?}"),
            );
            assert_eq!(read_wire(&db, oid, property), wire, "{oid:?} {property:?}");
        }
    }
}

#[test]
fn wp_lift_car_position_holds_to_unsigned8() {
    let (mut db, oid) = db_with(Box::new(LiftObject::new(1, "LIFT-1", 3).unwrap()));
    let car_position = PropertyIdentifier::CAR_POSITION;
    write(&mut db, oid, car_position, PropertyValue::Unsigned(255)).unwrap();
    assert_eq!(read_wire(&db, oid, car_position), [0x21, 0xFF]);
    for raw in [256u64, 70_000, u64::from(u32::MAX)] {
        assert_property_error(
            write(&mut db, oid, car_position, PropertyValue::Unsigned(raw)),
            ErrorCode::VALUE_OUT_OF_RANGE,
            &format!("Car_Position {raw}"),
        );
        assert_eq!(read_wire(&db, oid, car_position), [0x21, 0xFF]);
    }
}

#[test]
fn wp_lift_car_load_is_a_real_in_car_load_units() {
    let (mut db, oid) = db_with(Box::new(LiftObject::new(1, "LIFT-1", 3).unwrap()));
    let car_load = PropertyIdentifier::CAR_LOAD;
    // REAL 0.0, in PERCENT (98) until the application sets other units.
    assert_eq!(read_wire(&db, oid, car_load), [0x44, 0, 0, 0, 0]);
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::CAR_LOAD_UNITS),
        [0x91, 98]
    );
    // 250.5f32 is 0x437A8000: no percentage cap.
    write(&mut db, oid, car_load, PropertyValue::Real(250.5)).unwrap();
    let stored = [0x44, 0x43, 0x7A, 0x80, 0x00];
    assert_eq!(read_wire(&db, oid, car_load), stored);
    for (value, expected) in [
        (PropertyValue::Unsigned(50), ErrorCode::INVALID_DATA_TYPE),
        (PropertyValue::Real(f32::NAN), ErrorCode::VALUE_OUT_OF_RANGE),
        (
            PropertyValue::Real(f32::INFINITY),
            ErrorCode::VALUE_OUT_OF_RANGE,
        ),
    ] {
        assert_property_error(
            write(&mut db, oid, car_load, value.clone()),
            expected,
            &format!("Car_Load {value:?}"),
        );
        assert_eq!(read_wire(&db, oid, car_load), stored);
    }
}

#[test]
fn wp_lift_passenger_alarm_and_fault_signals_take_their_table_datatypes() {
    let (mut db, oid) = db_with(Box::new(LiftObject::new(1, "LIFT-1", 3).unwrap()));
    let alarm = PropertyIdentifier::PASSENGER_ALARM;
    let faults = PropertyIdentifier::FAULT_SIGNALS;
    assert_eq!(read_wire(&db, oid, alarm), [0x10]);
    write(&mut db, oid, alarm, PropertyValue::Boolean(true)).unwrap();
    assert_eq!(read_wire(&db, oid, alarm), [0x11]);

    assert_eq!(read_wire(&db, oid, faults), [0u8; 0]);
    // SAFETY_INTERLOCK_FAULT (5) and proprietary 1024.
    let set = PropertyValue::List(vec![
        PropertyValue::Enumerated(LiftFault::SAFETY_INTERLOCK_FAULT.to_raw()),
        PropertyValue::Enumerated(1024),
    ]);
    write(&mut db, oid, faults, set).unwrap();
    let stored = [0x91, 0x05, 0x92, 0x04, 0x00];
    assert_eq!(read_wire(&db, oid, faults), stored);
    for (value, context) in [
        (PropertyValue::Enumerated(17), "reserved 17"),
        (PropertyValue::Enumerated(65_536), "above 65535"),
        (
            PropertyValue::List(vec![
                PropertyValue::Enumerated(4),
                PropertyValue::Enumerated(4),
            ]),
            "duplicate",
        ),
    ] {
        assert_property_error(
            write(&mut db, oid, faults, value),
            ErrorCode::VALUE_OUT_OF_RANGE,
            context,
        );
        assert_eq!(read_wire(&db, oid, faults), stored, "{context}");
    }
    // An empty propertyValue clears the set.
    write(&mut db, oid, faults, PropertyValue::List(vec![])).unwrap();
    assert_eq!(read_wire(&db, oid, faults), [0u8; 0]);
}

#[test]
fn wp_lift_rows_outside_table_12_77_and_read_only_rows() {
    let (mut db, oid) = db_with(Box::new(LiftObject::new(1, "LIFT-1", 3).unwrap()));
    let before = read_wire(&db, oid, PropertyIdentifier::PROPERTY_LIST);
    // Not Table 12-77 rows (#1021).
    for property in [
        PropertyIdentifier::TRACKING_VALUE,
        PropertyIdentifier::FLOOR_NUMBER,
    ] {
        assert_property_error(
            write(&mut db, oid, property, PropertyValue::Unsigned(2)),
            ErrorCode::UNKNOWN_PROPERTY,
            &format!("{property:?}"),
        );
    }
    // Served rows the application owns.
    for (property, value) in [
        (
            PropertyIdentifier::CAR_DOOR_STATUS,
            PropertyValue::List(vec![PropertyValue::Enumerated(0)]),
        ),
        (
            PropertyIdentifier::LANDING_DOOR_STATUS,
            PropertyValue::ApplicationData(vec![0x0E, 0x0F]),
        ),
        (
            PropertyIdentifier::CAR_LOAD_UNITS,
            PropertyValue::Enumerated(39),
        ),
        (
            PropertyIdentifier::FLOOR_TEXT,
            PropertyValue::List(vec![PropertyValue::CharacterString("L".into())]),
        ),
    ] {
        let wire = read_wire(&db, oid, property);
        assert_property_error(
            write(&mut db, oid, property, value),
            ErrorCode::WRITE_ACCESS_DENIED,
            &format!("{property:?}"),
        );
        assert_eq!(read_wire(&db, oid, property), wire, "{property:?}");
    }
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::PROPERTY_LIST),
        before
    );
}
