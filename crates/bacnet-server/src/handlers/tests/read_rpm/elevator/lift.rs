//! The Lift's Table 12-77 projection over ReadProperty and
//! ReadPropertyMultiple, with the shared case table of the parent module.

use super::*;
use bacnet_objects::elevator::LiftObject;
use bacnet_types::constructed::{
    AssignedLandingCall, BACnetAssignedLandingCalls, BACnetDeviceObjectReference,
    BACnetLandingDoorStatus, BACnetLiftCarCallList, LandingDoor,
};
use bacnet_types::enums::{
    DoorStatus, EngineeringUnits, LiftCarDoorCommand, LiftCarDriveStatus, LiftCarMode,
};

#[test]
fn rpm_lift_indexed_reads_and_bytes_are_unchanged() {
    for configured in [false, true] {
        let mut object = LiftObject::new(7, "LIFT-7", 2).unwrap();
        if configured {
            object
                .set_elevator_group(ObjectIdentifier::new(ObjectType::ELEVATOR_GROUP, 3).unwrap())
                .unwrap();
            object.set_group_id(47);
            object.set_installation_id(2);
            object
                .set_car_door_status(vec![DoorStatus::CLOSED, DoorStatus::SAFETY_LOCKED])
                .unwrap();
            object
                .set_landing_door_status(vec![
                    BACnetLandingDoorStatus {
                        landing_doors: vec![LandingDoor {
                            floor_number: 1,
                            door_status: DoorStatus::CLOSED,
                        }],
                    },
                    BACnetLandingDoorStatus::default(),
                ])
                .unwrap();
            object
                .set_car_load_units(EngineeringUnits::KILOGRAMS)
                .unwrap();
            // The call and command arrays and the car-state rows (#1052).
            object
                .set_assigned_landing_calls(vec![
                    BACnetAssignedLandingCalls {
                        landing_calls: vec![AssignedLandingCall {
                            floor_number: 2,
                            direction: LiftCarDirection::UP,
                        }],
                    },
                    BACnetAssignedLandingCalls::default(),
                ])
                .unwrap();
            object.set_making_car_call(vec![2, 0]).unwrap();
            object
                .set_registered_car_call(vec![
                    BACnetLiftCarCallList {
                        floor_numbers: vec![2, 1],
                    },
                    BACnetLiftCarCallList::default(),
                ])
                .unwrap();
            object
                .set_car_door_command(vec![LiftCarDoorCommand::OPEN, LiftCarDoorCommand::NONE])
                .unwrap();
            object
                .set_car_assigned_direction(LiftCarDirection::DOWN)
                .unwrap();
            object.set_car_door_zone(true);
            object.set_car_mode(LiftCarMode::NORMAL).unwrap();
            object.set_next_stopping_floor(2);
            object
                .set_car_drive_status(LiftCarDriveStatus::DECELERATE)
                .unwrap();
            for (p, value) in [
                (P::CAR_POSITION, PropertyValue::Unsigned(2)),
                (
                    P::CAR_MOVING_DIRECTION,
                    PropertyValue::Enumerated(LiftCarDirection::DOWN.to_raw()),
                ),
                (P::CAR_LOAD, PropertyValue::Real(18.75)),
                (P::PASSENGER_ALARM, PropertyValue::Boolean(true)),
                (P::ENERGY_METER, PropertyValue::Real(12.5)),
                (
                    P::FAULT_SIGNALS,
                    PropertyValue::List(vec![
                        PropertyValue::Enumerated(0),
                        PropertyValue::Enumerated(2048),
                    ]),
                ),
            ] {
                object.write_property(p, None, value, None).unwrap();
            }
            // A meter in another device, so Energy_Meter reads 0.0 (#1036).
            object
                .set_energy_meter_ref(BACnetDeviceObjectReference {
                    device_identifier: Some(ObjectIdentifier::new(ObjectType::DEVICE, 9).unwrap()),
                    object_identifier: ObjectIdentifier::new(ObjectType::ACCUMULATOR, 3).unwrap(),
                })
                .unwrap();
        }
        write_common(&mut object, configured);
        let oid = object.object_identifier();
        let mut db = ObjectDatabase::new();
        db.add(Box::new(object)).unwrap();
        // Independent application-value bytes pin the Table 12-77 projection.
        // "Floor N" encodes with an extended length octet: 0x75 0x08 0x00 +
        // text (tag 7, ANSI). 18.75f32 is 0x41960000.
        let floor_1: &[u8] = &[0x75, 0x08, 0x00, b'F', b'l', b'o', b'o', b'r', b' ', b'1'];
        let floor_text: &[u8] = &[
            0x75, 0x08, 0x00, b'F', b'l', b'o', b'o', b'r', b' ', b'1', 0x75, 0x08, 0x00, b'F',
            b'l', b'o', b'o', b'r', b' ', b'2',
        ];
        // Landing_Door_Status elements: landing-doors [0] frames of
        // floor [0] / door-status [1] pairs.
        let first_landing: &[u8] = if configured {
            &[0x0E, 0x09, 0x01, 0x19, 0x00, 0x0F]
        } else {
            &[0x0E, 0x0F]
        };
        let landing: &[u8] = if configured {
            &[0x0E, 0x09, 0x01, 0x19, 0x00, 0x0F, 0x0E, 0x0F]
        } else {
            &[0x0E, 0x0F]
        };
        let not_array = Err(ErrorCode::PROPERTY_IS_NOT_AN_ARRAY);
        let cases: &[(P, Option<u32>, ExpectedRead)] = &[
            (
                P::STATUS_FLAGS,
                None,
                Ok(if configured {
                    &[0x82, 4, 0x10]
                } else {
                    &[0x82, 4, 0]
                }),
            ),
            (P::STATUS_FLAGS, Some(0), not_array),
            (
                P::ELEVATOR_GROUP,
                None,
                Ok(if configured {
                    &[0xC4, 0x0E, 0x40, 0x00, 0x03]
                } else {
                    &[0xC4, 0x0E, 0x7F, 0xFF, 0xFF]
                }),
            ),
            (P::ELEVATOR_GROUP, Some(0), not_array),
            (
                P::GROUP_ID,
                None,
                Ok(if configured { &[0x21, 47] } else { &[0x21, 0] }),
            ),
            (P::GROUP_ID, Some(1), not_array),
            (
                P::INSTALLATION_ID,
                None,
                Ok(if configured { &[0x21, 2] } else { &[0x21, 0] }),
            ),
            (P::INSTALLATION_ID, Some(0), not_array),
            // Floor_Text is a BACnetARRAY indexed by universal floor number.
            (P::FLOOR_TEXT, None, Ok(floor_text)),
            (P::FLOOR_TEXT, Some(0), Ok(&[0x21, 2])),
            (P::FLOOR_TEXT, Some(1), Ok(floor_1)),
            (P::FLOOR_TEXT, Some(3), Err(ErrorCode::INVALID_ARRAY_INDEX)),
            // BACnetARRAY of BACnetAssignedLandingCalls: landing-calls [0]
            // frames of floor [0] / direction [1] pairs; floor 2 UP (3).
            (
                P::ASSIGNED_LANDING_CALLS,
                None,
                Ok(if configured {
                    &[0x0E, 0x09, 0x02, 0x19, 0x03, 0x0F, 0x0E, 0x0F]
                } else {
                    &[0x0E, 0x0F]
                }),
            ),
            (
                P::ASSIGNED_LANDING_CALLS,
                Some(0),
                Ok(if configured { &[0x21, 2] } else { &[0x21, 1] }),
            ),
            (
                P::ASSIGNED_LANDING_CALLS,
                Some(1),
                Ok(if configured {
                    &[0x0E, 0x09, 0x02, 0x19, 0x03, 0x0F]
                } else {
                    &[0x0E, 0x0F]
                }),
            ),
            (
                P::ASSIGNED_LANDING_CALLS,
                Some(3),
                Err(ErrorCode::INVALID_ARRAY_INDEX),
            ),
            // BACnetARRAY of Unsigned8, 0 where no car call was made.
            (
                P::MAKING_CAR_CALL,
                None,
                Ok(if configured {
                    &[0x21, 2, 0x21, 0]
                } else {
                    &[0x21, 0]
                }),
            ),
            (
                P::MAKING_CAR_CALL,
                Some(1),
                Ok(if configured { &[0x21, 2] } else { &[0x21, 0] }),
            ),
            // BACnetARRAY of BACnetLiftCarCallList: floor-numbers [0] frames
            // of application Unsigned floors.
            (
                P::REGISTERED_CAR_CALL,
                None,
                Ok(if configured {
                    &[0x0E, 0x21, 0x02, 0x21, 0x01, 0x0F, 0x0E, 0x0F]
                } else {
                    &[0x0E, 0x0F]
                }),
            ),
            (
                P::REGISTERED_CAR_CALL,
                Some(0),
                Ok(if configured { &[0x21, 2] } else { &[0x21, 1] }),
            ),
            (
                P::REGISTERED_CAR_CALL,
                Some(3),
                Err(ErrorCode::INVALID_ARRAY_INDEX),
            ),
            // Car_Position is an Unsigned8.
            (
                P::CAR_POSITION,
                None,
                Ok(if configured { &[0x21, 2] } else { &[0x21, 1] }),
            ),
            (P::CAR_POSITION, Some(0), not_array),
            // A fresh lift is STOPPED (2); DOWN is 4.
            (
                P::CAR_MOVING_DIRECTION,
                None,
                Ok(if configured { &[0x91, 4] } else { &[0x91, 2] }),
            ),
            (P::CAR_MOVING_DIRECTION, Some(0), not_array),
            // A fresh lift's assigned direction is UNKNOWN (0).
            (
                P::CAR_ASSIGNED_DIRECTION,
                None,
                Ok(if configured { &[0x91, 4] } else { &[0x91, 0] }),
            ),
            (P::CAR_ASSIGNED_DIRECTION, Some(0), not_array),
            // BACnetARRAY of BACnetDoorStatus: one UNKNOWN (2) door, or
            // CLOSED (0) and SAFETY_LOCKED (8).
            (
                P::CAR_DOOR_STATUS,
                None,
                Ok(if configured {
                    &[0x91, 0, 0x91, 8]
                } else {
                    &[0x91, 2]
                }),
            ),
            (
                P::CAR_DOOR_STATUS,
                Some(0),
                Ok(if configured { &[0x21, 2] } else { &[0x21, 1] }),
            ),
            (
                P::CAR_DOOR_STATUS,
                Some(1),
                Ok(if configured { &[0x91, 0] } else { &[0x91, 2] }),
            ),
            (
                P::CAR_DOOR_STATUS,
                Some(3),
                Err(ErrorCode::INVALID_ARRAY_INDEX),
            ),
            // BACnetARRAY of BACnetLiftCarDoorCommand: OPEN (1) and NONE (0).
            (
                P::CAR_DOOR_COMMAND,
                None,
                Ok(if configured {
                    &[0x91, 1, 0x91, 0]
                } else {
                    &[0x91, 0]
                }),
            ),
            (
                P::CAR_DOOR_COMMAND,
                Some(1),
                Ok(if configured { &[0x91, 1] } else { &[0x91, 0] }),
            ),
            (
                P::CAR_DOOR_ZONE,
                None,
                Ok(if configured { &[0x11] } else { &[0x10] }),
            ),
            (P::CAR_DOOR_ZONE, Some(0), not_array),
            // UNKNOWN (0) or NORMAL (1).
            (
                P::CAR_MODE,
                None,
                Ok(if configured { &[0x91, 1] } else { &[0x91, 0] }),
            ),
            (P::CAR_MODE, Some(0), not_array),
            // Car_Load is a REAL in Car_Load_Units: PERCENT (98) or
            // KILOGRAMS (39).
            (
                P::CAR_LOAD,
                None,
                Ok(if configured {
                    &[0x44, 0x41, 0x96, 0x00, 0x00]
                } else {
                    &[0x44, 0, 0, 0, 0]
                }),
            ),
            (P::CAR_LOAD, Some(0), not_array),
            (
                P::CAR_LOAD_UNITS,
                None,
                Ok(if configured { &[0x91, 39] } else { &[0x91, 98] }),
            ),
            (P::CAR_LOAD_UNITS, Some(0), not_array),
            // A fresh lift's car stands at floor 1.
            (
                P::NEXT_STOPPING_FLOOR,
                None,
                Ok(if configured { &[0x21, 2] } else { &[0x21, 1] }),
            ),
            (P::NEXT_STOPPING_FLOOR, Some(0), not_array),
            (
                P::PASSENGER_ALARM,
                None,
                Ok(if configured { &[0x11] } else { &[0x10] }),
            ),
            (P::PASSENGER_ALARM, Some(0), not_array),
            // REAL 0.0 either way: the configured lift names a meter.
            (P::ENERGY_METER, None, Ok(&[0x44, 0, 0, 0, 0])),
            (P::ENERGY_METER, Some(0), not_array),
            // BACnetDeviceObjectReference: device [0] Device 9 (type 8) then
            // object [1] Accumulator (type 23) 3, or the uninitialized
            // Accumulator 4194303 with no device.
            (
                P::ENERGY_METER_REF,
                None,
                Ok(if configured {
                    &[0x0C, 0x02, 0x00, 0x00, 0x09, 0x1C, 0x05, 0xC0, 0x00, 0x03]
                } else {
                    &[0x1C, 0x05, 0xFF, 0xFF, 0xFF]
                }),
            ),
            (P::ENERGY_METER_REF, Some(0), not_array),
            (P::RELIABILITY, None, Ok(&[0x91, 0])),
            (P::RELIABILITY, Some(0), not_array),
            (
                P::OUT_OF_SERVICE,
                None,
                Ok(if configured { &[0x11] } else { &[0x10] }),
            ),
            (P::OUT_OF_SERVICE, Some(0), not_array),
            // UNKNOWN (0) or DECELERATE (4).
            (
                P::CAR_DRIVE_STATUS,
                None,
                Ok(if configured { &[0x91, 4] } else { &[0x91, 0] }),
            ),
            (P::CAR_DRIVE_STATUS, Some(0), not_array),
            // BACnetLIST of BACnetLiftFault, so any index is refused.
            (
                P::FAULT_SIGNALS,
                None,
                Ok(if configured {
                    &[0x91, 0, 0x92, 0x08, 0x00]
                } else {
                    EMPTY
                }),
            ),
            (P::FAULT_SIGNALS, Some(1), not_array),
            (P::LANDING_DOOR_STATUS, None, Ok(landing)),
            (
                P::LANDING_DOOR_STATUS,
                Some(0),
                Ok(if configured { &[0x21, 2] } else { &[0x21, 1] }),
            ),
            (P::LANDING_DOOR_STATUS, Some(1), Ok(first_landing)),
            (
                P::LANDING_DOOR_STATUS,
                Some(3),
                Err(ErrorCode::INVALID_ARRAY_INDEX),
            ),
            (
                P::PROPERTY_LIST,
                None,
                Ok(&[
                    0x91, 28, 0x91, 111, 0x92, 0x01, 0xCB, 0x92, 0x01, 0xD1, 0x92, 0x01, 0xD5,
                    0x92, 0x01, 0xD0, 0x92, 0x01, 0xBF, 0x92, 0x01, 0xDB, 0x92, 0x01, 0xE0, 0x92,
                    0x01, 0xCA, 0x92, 0x01, 0xC9, 0x92, 0x01, 0xC0, 0x92, 0x01, 0xC2, 0x92, 0x01,
                    0xC1, 0x92, 0x01, 0xC4, 0x92, 0x01, 0xC8, 0x92, 0x01, 0xC6, 0x92, 0x01, 0xC7,
                    0x92, 0x01, 0xDC, 0x92, 0x01, 0xDE, 0x92, 0x01, 0xCC, 0x92, 0x01, 0xCD, 0x91,
                    103, 0x91, 81, 0x92, 0x01, 0xC5, 0x92, 0x01, 0xCF, 0x92, 0x01, 0xD8,
                ]),
            ),
            (P::PROPERTY_LIST, Some(0), Ok(&[0x21, 27])),
            (P::PROPERTY_LIST, Some(2), Ok(&[0x91, 111])),
            (P::PROPERTY_LIST, Some(6), Ok(&[0x92, 0x01, 0xD0])),
            // Assigned_Landing_Calls (447) follows Floor_Text in table order.
            (P::PROPERTY_LIST, Some(7), Ok(&[0x92, 0x01, 0xBF])),
            (P::PROPERTY_LIST, Some(22), Ok(&[0x92, 0x01, 0xCD])),
            (P::PROPERTY_LIST, Some(27), Ok(&[0x92, 0x01, 0xD8])),
            (
                P::PROPERTY_LIST,
                Some(28),
                Err(ErrorCode::INVALID_ARRAY_INDEX),
            ),
            (
                P::PROPERTY_LIST,
                Some(u32::MAX),
                Err(ErrorCode::INVALID_ARRAY_INDEX),
            ),
            // Tracking_Value and Floor_Number aren't Table 12-77 rows
            // (#1021); Car_Door_Text is an optional row the object doesn't
            // serve.
            (P::TRACKING_VALUE, None, Err(ErrorCode::UNKNOWN_PROPERTY)),
            (P::TRACKING_VALUE, Some(0), not_array),
            (P::FLOOR_NUMBER, None, Err(ErrorCode::UNKNOWN_PROPERTY)),
            (P::CAR_DOOR_TEXT, None, Err(ErrorCode::UNKNOWN_PROPERTY)),
        ];
        assert_cases(&db, oid, cases);
    }
}
