//! Door_Status, Lock_Status and Door_Alarm_State writes on an Access Door over
//! WriteProperty and WritePropertyMultiple: taken while Out_Of_Service is
//! TRUE, refused in service (Clause 12.26.9, Table 12-30 footnote 1, #1131).

use super::*;
use bacnet_objects::access_control::AccessDoorObject;
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_types::enums::{DoorAlarmState, DoorStatus, LockStatus};

/// An in-service door whose device reports it open, unlocked and held open
/// too long.
fn door_db() -> (ObjectDatabase, ObjectIdentifier) {
    let mut door = AccessDoorObject::new(1, "DOOR-1").unwrap();
    door.set_door_status(DoorStatus::OPENED);
    door.set_lock_status(LockStatus::UNLOCKED);
    door.set_door_alarm_state(DoorAlarmState::DOOR_OPEN_TOO_LONG);
    let oid = door.object_identifier();
    let mut db = ObjectDatabase::new();
    db.add(Box::new(door)).unwrap();
    (db, oid)
}

fn encode(value: &PropertyValue) -> Vec<u8> {
    let mut buf = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut buf, value).unwrap();
    buf.to_vec()
}

fn enumerated(raw: u32) -> PropertyValue {
    PropertyValue::Enumerated(raw)
}

fn write_property(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: None,
        property_value: encode(&value),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property(db, &request).map(|_| ())
}

fn write_property_multiple(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    writes: &[(PropertyIdentifier, PropertyValue)],
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
fn read_bytes(db: &ObjectDatabase, oid: ObjectIdentifier, property: PropertyIdentifier) -> Vec<u8> {
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

/// Door_Status, Lock_Status and Door_Alarm_State as served, in wire bytes.
fn served(db: &ObjectDatabase, oid: ObjectIdentifier) -> [Vec<u8>; 3] {
    ROWS.map(|property| read_bytes(db, oid, property))
}

fn assert_property_error(result: Result<(), Error>, expected: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class, code })
            if class == ErrorClass::PROPERTY.to_raw() as u32
                && code == expected.to_raw() as u32),
        "expected PROPERTY / {expected:?}, got {result:?}"
    );
}

const ROWS: [PropertyIdentifier; 3] = [
    PropertyIdentifier::DOOR_STATUS,
    PropertyIdentifier::LOCK_STATUS,
    PropertyIdentifier::DOOR_ALARM_STATE,
];
/// The device's values: OPENED, UNLOCKED, DOOR_OPEN_TOO_LONG.
const DEVICE: [[u8; 2]; 3] = [[0x91, 1], [0x91, 1], [0x91, 2]];
/// The simulated values: DOOR_FAULT, LOCK_FAULT, FORCED_OPEN.
const SIMULATED: [[u8; 2]; 3] = [[0x91, 3], [0x91, 2], [0x91, 3]];
/// Status_Flags with only OUT_OF_SERVICE set.
const OUT_OF_SERVICE_FLAGS: [u8; 3] = [0x82, 0x04, 0x10];

fn simulation() -> [(PropertyIdentifier, PropertyValue); 3] {
    [
        (ROWS[0], enumerated(DoorStatus::DOOR_FAULT.to_raw())),
        (ROWS[1], enumerated(LockStatus::LOCK_FAULT.to_raw())),
        (ROWS[2], enumerated(DoorAlarmState::FORCED_OPEN.to_raw())),
    ]
}

#[test]
fn write_property_takes_door_status_rows_only_out_of_service() {
    let (mut db, oid) = door_db();
    for (property, value) in simulation() {
        assert_property_error(
            write_property(&mut db, oid, property, value),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
    assert_eq!(served(&db, oid), DEVICE.map(Vec::from));

    write_property(
        &mut db,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(true),
    )
    .unwrap();
    for (index, (property, value)) in simulation().into_iter().enumerate() {
        write_property(&mut db, oid, property, value).unwrap();
        assert_eq!(read_bytes(&db, oid, property), SIMULATED[index]);
    }
    assert_eq!(
        read_bytes(&db, oid, PropertyIdentifier::STATUS_FLAGS),
        OUT_OF_SERVICE_FLAGS
    );
    // Present_Value is untouched by the simulation.
    assert_eq!(
        read_bytes(&db, oid, PropertyIdentifier::PRESENT_VALUE),
        [0x91, 0]
    );

    // The return to service serves the device's values again.
    write_property(
        &mut db,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(false),
    )
    .unwrap();
    assert_eq!(served(&db, oid), DEVICE.map(Vec::from));
    for (property, value) in simulation() {
        assert_property_error(
            write_property(&mut db, oid, property, value),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
}

#[test]
fn write_property_multiple_takes_door_status_rows_only_out_of_service() {
    let (mut db, oid) = door_db();
    // In service the first write is refused and nothing changes; so is each
    // row on its own.
    assert_property_error(
        write_property_multiple(&mut db, oid, &simulation()),
        ErrorCode::WRITE_ACCESS_DENIED,
    );
    for write in simulation() {
        assert_property_error(
            write_property_multiple(&mut db, oid, &[write]),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
    assert_eq!(served(&db, oid), DEVICE.map(Vec::from));

    // Out_Of_Service first, then the three simulated values, in one request.
    let mut writes = vec![(
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(true),
    )];
    writes.extend(simulation());
    write_property_multiple(&mut db, oid, &writes).unwrap();
    assert_eq!(served(&db, oid), SIMULATED.map(Vec::from));
    assert_eq!(
        read_bytes(&db, oid, PropertyIdentifier::STATUS_FLAGS),
        OUT_OF_SERVICE_FLAGS
    );

    // A simulated value and the return to service in one request: the
    // device's values come back and the simulation is dropped.
    write_property_multiple(
        &mut db,
        oid,
        &[
            (
                PropertyIdentifier::DOOR_ALARM_STATE,
                enumerated(DoorAlarmState::TAMPER.to_raw()),
            ),
            (
                PropertyIdentifier::OUT_OF_SERVICE,
                PropertyValue::Boolean(false),
            ),
        ],
    )
    .unwrap();
    assert_eq!(served(&db, oid), DEVICE.map(Vec::from));
    assert_property_error(
        write_property_multiple(&mut db, oid, &simulation()),
        ErrorCode::WRITE_ACCESS_DENIED,
    );
}

#[test]
fn door_status_row_writes_outside_their_datatypes_are_refused_unchanged() {
    let (mut db, oid) = door_db();
    write_property(
        &mut db,
        oid,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(true),
    )
    .unwrap();
    for (property, value, code) in [
        // 10 is reserved for ASHRAE, 65536 past the datatype.
        (ROWS[0], enumerated(10), ErrorCode::VALUE_OUT_OF_RANGE),
        (ROWS[0], enumerated(65_536), ErrorCode::VALUE_OUT_OF_RANGE),
        (
            ROWS[0],
            PropertyValue::Unsigned(1),
            ErrorCode::INVALID_DATA_TYPE,
        ),
        // BACnetLockStatus has no proprietary range.
        (ROWS[1], enumerated(5), ErrorCode::VALUE_OUT_OF_RANGE),
        (ROWS[1], enumerated(1_024), ErrorCode::VALUE_OUT_OF_RANGE),
        (ROWS[1], PropertyValue::Null, ErrorCode::INVALID_DATA_TYPE),
        // 9 is reserved for ASHRAE.
        (ROWS[2], enumerated(9), ErrorCode::VALUE_OUT_OF_RANGE),
        (ROWS[2], enumerated(65_536), ErrorCode::VALUE_OUT_OF_RANGE),
        (
            ROWS[2],
            PropertyValue::Boolean(true),
            ErrorCode::INVALID_DATA_TYPE,
        ),
    ] {
        assert_property_error(write_property(&mut db, oid, property, value.clone()), code);
        assert_eq!(served(&db, oid), DEVICE.map(Vec::from), "{property:?}");
        // WPM stops at the refused value after committing the valid one
        // before it.
        assert_property_error(
            write_property_multiple(
                &mut db,
                oid,
                &[
                    (
                        PropertyIdentifier::DOOR_STATUS,
                        enumerated(DoorStatus::DOOR_FAULT.to_raw()),
                    ),
                    (property, value),
                ],
            ),
            code,
        );
        assert_eq!(
            served(&db, oid),
            [SIMULATED[0], DEVICE[1], DEVICE[2]].map(Vec::from),
            "{property:?}"
        );
        write_property(
            &mut db,
            oid,
            PropertyIdentifier::DOOR_STATUS,
            enumerated(DoorStatus::OPENED.to_raw()),
        )
        .unwrap();
    }
    // The proprietary ranges go through and read back.
    for (property, raw, bytes) in [
        (ROWS[0], 1_024, vec![0x92, 0x04, 0x00]),
        (ROWS[2], 256, vec![0x92, 0x01, 0x00]),
    ] {
        write_property(&mut db, oid, property, enumerated(raw)).unwrap();
        assert_eq!(read_bytes(&db, oid, property), bytes);
    }
}
