//! The Lift's call and command arrays and car-state rows over WriteProperty
//! and ReadProperty (#1052): read-only in service, and written as the whole
//! array, one element or one value while Out_Of_Service is TRUE.

use super::*;

/// Each row with a valid propertyValue for a two-door Lift and the array
/// index it is written at.
const WRITES: [(PropertyIdentifier, Option<u32>, &[u8]); 9] = [
    // Door 1: floor 3 DOWN (4); door 2: none.
    (
        PropertyIdentifier::ASSIGNED_LANDING_CALLS,
        None,
        &[0x0E, 0x09, 0x03, 0x19, 0x04, 0x0F, 0x0E, 0x0F],
    ),
    (
        PropertyIdentifier::MAKING_CAR_CALL,
        None,
        &[0x21, 0x05, 0x21, 0x00],
    ),
    // Door 2: floors 5 and 6.
    (
        PropertyIdentifier::REGISTERED_CAR_CALL,
        Some(2),
        &[0x0E, 0x21, 0x05, 0x21, 0x06, 0x0F],
    ),
    // OPEN (1) on door 2.
    (PropertyIdentifier::CAR_DOOR_COMMAND, Some(2), &[0x91, 0x01]),
    // DOWN (4), TRUE, FIREFIGHTER_CONTROL (6), floor 5, RATED_SPEED (5).
    (
        PropertyIdentifier::CAR_ASSIGNED_DIRECTION,
        None,
        &[0x91, 0x04],
    ),
    (PropertyIdentifier::CAR_DOOR_ZONE, None, &[0x11]),
    (PropertyIdentifier::CAR_MODE, None, &[0x91, 0x06]),
    (PropertyIdentifier::NEXT_STOPPING_FLOOR, None, &[0x21, 0x05]),
    (PropertyIdentifier::CAR_DRIVE_STATUS, None, &[0x91, 0x05]),
];

/// A two-door Lift in service.
fn two_door_lift() -> (ObjectDatabase, ObjectIdentifier) {
    let mut lift = LiftObject::new(1, "LIFT-1", 6).unwrap();
    lift.set_car_door_status(vec![DoorStatus::CLOSED, DoorStatus::CLOSED])
        .unwrap();
    db_with(Box::new(lift))
}

#[test]
fn wp_lift_call_arrays_and_car_state_take_simulation_writes_only_out_of_service() {
    let (mut db, oid) = two_door_lift();
    let read_all = |db: &ObjectDatabase| -> Vec<Vec<u8>> {
        WRITES
            .iter()
            .map(|&(property, _, _)| read_wire(db, oid, property))
            .collect()
    };
    // A new Lift: no calls, no pending commands, UNKNOWN direction, mode and
    // drive status, outside the door zone, stopping next at floor 1.
    let fresh = read_all(&db);
    assert_eq!(
        fresh,
        [
            vec![0x0E, 0x0F, 0x0E, 0x0F],
            vec![0x21, 0x00, 0x21, 0x00],
            vec![0x0E, 0x0F, 0x0E, 0x0F],
            vec![0x91, 0x00, 0x91, 0x00],
            vec![0x91, 0x00],
            vec![0x10],
            vec![0x91, 0x00],
            vec![0x21, 0x01],
            vec![0x91, 0x00],
        ]
    );
    for (property, index, value) in WRITES {
        assert_property_error(
            write_at(&mut db, oid, property, index, value),
            ErrorCode::WRITE_ACCESS_DENIED,
            &format!("in service {property:?}"),
        );
    }
    assert_eq!(read_all(&db), fresh);

    write(
        &mut db,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(true),
    )
    .unwrap();
    for (property, index, value) in WRITES {
        write_at(&mut db, oid, property, index, value)
            .unwrap_or_else(|e| panic!("{property:?}: {e:?}"));
        assert_eq!(
            read_wire_at(&db, oid, property, index).unwrap(),
            value,
            "{property:?}"
        );
    }
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::REGISTERED_CAR_CALL),
        [0x0E, 0x0F, 0x0E, 0x21, 0x05, 0x21, 0x06, 0x0F]
    );
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::CAR_DOOR_COMMAND),
        [0x91, 0x00, 0x91, 0x01]
    );
}

#[test]
fn wp_lift_call_arrays_and_car_state_refuse_bad_values_out_of_service() {
    let (mut db, oid) = two_door_lift();
    write(
        &mut db,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(true),
    )
    .unwrap();
    let before: Vec<_> = WRITES
        .iter()
        .map(|&(property, _, _)| read_wire(&db, oid, property))
        .collect();
    // (property, array index, propertyValue, expected error, context)
    type Case = (
        PropertyIdentifier,
        Option<u32>,
        &'static [u8],
        ErrorCode,
        &'static str,
    );
    let cases: &[Case] = &[
        (
            PropertyIdentifier::ASSIGNED_LANDING_CALLS,
            Some(1),
            &[0x0E, 0x09, 0x03, 0x19, 0x06, 0x0F],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "reserved direction 6",
        ),
        (
            PropertyIdentifier::ASSIGNED_LANDING_CALLS,
            Some(1),
            &[0x0E, 0x0A, 0x01, 0x00, 0x19, 0x03, 0x0F],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "floor 256",
        ),
        (
            PropertyIdentifier::ASSIGNED_LANDING_CALLS,
            Some(1),
            &[0x0E, 0x09, 0x03, 0x0F],
            ErrorCode::INVALID_DATA_ENCODING,
            "floor without direction",
        ),
        (
            PropertyIdentifier::ASSIGNED_LANDING_CALLS,
            None,
            &[0x0E, 0x0F],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "one element for two car doors",
        ),
        (
            PropertyIdentifier::MAKING_CAR_CALL,
            Some(1),
            &[0x22, 0x01, 0x00],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "floor 256",
        ),
        (
            PropertyIdentifier::MAKING_CAR_CALL,
            Some(0),
            &[0x21, 0x03],
            ErrorCode::WRITE_ACCESS_DENIED,
            "size",
        ),
        (
            PropertyIdentifier::REGISTERED_CAR_CALL,
            Some(1),
            &[0x0E, 0x22, 0x01, 0x00, 0x0F],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "floor 256",
        ),
        (
            PropertyIdentifier::REGISTERED_CAR_CALL,
            Some(3),
            &[0x0E, 0x0F],
            ErrorCode::INVALID_ARRAY_INDEX,
            "door 3",
        ),
        (
            PropertyIdentifier::REGISTERED_CAR_CALL,
            Some(1),
            &[0x21, 0x05],
            ErrorCode::INVALID_DATA_TYPE,
            "bare floor",
        ),
        (
            PropertyIdentifier::CAR_DOOR_COMMAND,
            Some(1),
            &[0x91, 0x03],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "command 3",
        ),
        (
            PropertyIdentifier::CAR_ASSIGNED_DIRECTION,
            None,
            &[0x92, 0x03, 0xFF],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "reserved direction 1023",
        ),
        (
            PropertyIdentifier::CAR_DOOR_ZONE,
            None,
            &[0x91, 0x01],
            ErrorCode::INVALID_DATA_TYPE,
            "Enumerated zone",
        ),
        (
            PropertyIdentifier::CAR_MODE,
            None,
            &[0x91, 0x0E],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "reserved mode 14",
        ),
        (
            PropertyIdentifier::NEXT_STOPPING_FLOOR,
            None,
            &[0x22, 0x01, 0x00],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "floor 256",
        ),
        (
            PropertyIdentifier::CAR_DRIVE_STATUS,
            None,
            &[0x91, 0x0A],
            ErrorCode::VALUE_OUT_OF_RANGE,
            "reserved drive status 10",
        ),
        (
            PropertyIdentifier::CAR_DRIVE_STATUS,
            None,
            &[0x21, 0x01],
            ErrorCode::INVALID_DATA_TYPE,
            "Unsigned drive status",
        ),
    ];
    for &(property, index, value, expected, context) in cases {
        assert_property_error(
            write_at(&mut db, oid, property, index, value),
            expected,
            &format!("{property:?} {index:?} {context}"),
        );
    }
    let after: Vec<_> = WRITES
        .iter()
        .map(|&(property, _, _)| read_wire(&db, oid, property))
        .collect();
    assert_eq!(after, before);
}
