//! Car_Door_Status and Landing_Door_Status take WriteProperty while the Lift
//! is out of service, as item (c) of its Out_Of_Service description asks
//! (Clause 12.59; #1035): the whole array or one element, but never the size,
//! which is the car door count the application sets.

use super::super::*;
use super::{
    assert_invalid_data_type, assert_property_error, assert_value_out_of_range, frame,
    set_out_of_service,
};
use bacnet_types::constructed::{BACnetLandingDoorStatus, LandingDoor};
use bacnet_types::enums::{DoorStatus, ErrorCode};

type P = PropertyIdentifier;

/// A two-door Lift, out of service.
fn simulated_lift() -> LiftObject {
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    lift.set_car_door_status(vec![DoorStatus::CLOSED, DoorStatus::CLOSED])
        .unwrap();
    set_out_of_service(&mut lift, true);
    lift
}

fn door(status: DoorStatus) -> PropertyValue {
    PropertyValue::Enumerated(status.to_raw())
}

fn landing(doors: &[(u8, DoorStatus)]) -> BACnetLandingDoorStatus {
    BACnetLandingDoorStatus {
        landing_doors: doors
            .iter()
            .map(|&(floor_number, door_status)| LandingDoor {
                floor_number,
                door_status,
            })
            .collect(),
    }
}

#[test]
fn lift_car_door_status_takes_whole_and_element_writes_out_of_service() {
    let mut lift = simulated_lift();
    let whole = PropertyValue::List(vec![
        door(DoorStatus::OPENING),
        door(DoorStatus::from_raw(1024)),
    ]);
    lift.write_property(P::CAR_DOOR_STATUS, None, whole.clone(), None)
        .unwrap();
    assert_eq!(
        lift.car_door_status(),
        [DoorStatus::OPENING, DoorStatus::from_raw(1024)]
    );
    assert_eq!(lift.read_property(P::CAR_DOOR_STATUS, None).unwrap(), whole);
    lift.write_property(
        P::CAR_DOOR_STATUS,
        Some(2),
        door(DoorStatus::SAFETY_LOCKED),
        None,
    )
    .unwrap();
    assert_eq!(
        lift.car_door_status(),
        [DoorStatus::OPENING, DoorStatus::SAFETY_LOCKED]
    );
    assert_eq!(
        lift.read_property(P::CAR_DOOR_STATUS, Some(2)).unwrap(),
        PropertyValue::Enumerated(8)
    );
    // The landing doors are untouched and keep one element per car door.
    assert_eq!(
        lift.landing_door_status(),
        [
            BACnetLandingDoorStatus::default(),
            BACnetLandingDoorStatus::default()
        ]
    );

    // A one-door car's whole array arrives from the service decoder as the
    // bare element.
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    set_out_of_service(&mut lift, true);
    lift.write_property(P::CAR_DOOR_STATUS, None, door(DoorStatus::OPENED), None)
        .unwrap();
    assert_eq!(lift.car_door_status(), [DoorStatus::OPENED]);
}

#[test]
fn lift_landing_door_status_takes_whole_and_element_writes_out_of_service() {
    let mut lift = simulated_lift();
    // Car door 1 pairs with floor 1 CLOSED and floor 2 SAFETY_LOCKED; car
    // door 2 with no landing door.
    let first = [0x0E, 0x09, 0x01, 0x19, 0x00, 0x09, 0x02, 0x19, 0x08, 0x0F];
    lift.write_property(
        P::LANDING_DOOR_STATUS,
        None,
        PropertyValue::List(vec![frame(&first), frame(&[0x0E, 0x0F])]),
        None,
    )
    .unwrap();
    assert_eq!(
        lift.landing_door_status(),
        [
            landing(&[(1, DoorStatus::CLOSED), (2, DoorStatus::SAFETY_LOCKED)]),
            landing(&[]),
        ]
    );
    // Car door 2 now pairs with floor 3, proprietary status 1024.
    let second = [0x0E, 0x09, 0x03, 0x1A, 0x04, 0x00, 0x0F];
    lift.write_property(P::LANDING_DOOR_STATUS, Some(2), frame(&second), None)
        .unwrap();
    assert_eq!(
        lift.landing_door_status()[1],
        landing(&[(3, DoorStatus::from_raw(1024))])
    );
    assert_eq!(
        lift.read_property(P::LANDING_DOOR_STATUS, None).unwrap(),
        PropertyValue::List(vec![frame(&first), frame(&second)])
    );
    assert_eq!(
        lift.car_door_status(),
        [DoorStatus::CLOSED, DoorStatus::CLOSED]
    );

    // A one-door car's whole array arrives as the bare frame.
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    set_out_of_service(&mut lift, true);
    lift.write_property(
        P::LANDING_DOOR_STATUS,
        None,
        frame(&[0x0E, 0x09, 0x02, 0x19, 0x01, 0x0F]),
        None,
    )
    .unwrap();
    assert_eq!(
        lift.landing_door_status(),
        [landing(&[(2, DoorStatus::OPENED)])]
    );
}

#[test]
fn lift_door_array_writes_cannot_change_the_door_count() {
    let mut lift = simulated_lift();
    let empty = || frame(&[0x0E, 0x0F]);
    for (property, too_few, too_many, element) in [
        (
            P::CAR_DOOR_STATUS,
            PropertyValue::List(vec![door(DoorStatus::OPENED)]),
            PropertyValue::List(vec![door(DoorStatus::OPENED); 3]),
            door(DoorStatus::OPENED),
        ),
        (
            P::LANDING_DOOR_STATUS,
            PropertyValue::List(vec![empty()]),
            PropertyValue::List(vec![empty(), empty(), empty()]),
            empty(),
        ),
    ] {
        let before = lift.read_property(property, None).unwrap();
        for (value, context) in [
            (too_few, "one element"),
            (too_many, "three elements"),
            (PropertyValue::List(vec![]), "no element"),
        ] {
            assert_value_out_of_range(
                lift.write_property(property, None, value, None),
                &format!("{property:?} {context}"),
            );
        }
        // The size isn't writable, and an element past it doesn't exist.
        assert_property_error(
            lift.write_property(property, Some(0), PropertyValue::Unsigned(3), None),
            ErrorCode::WRITE_ACCESS_DENIED,
            &format!("{property:?} [0]"),
        );
        for index in [3, u32::MAX] {
            assert_property_error(
                lift.write_property(property, Some(index), element.clone(), None),
                ErrorCode::INVALID_ARRAY_INDEX,
                &format!("{property:?} [{index}]"),
            );
        }
        assert_eq!(
            lift.read_property(property, None).unwrap(),
            before,
            "{property:?}"
        );
    }
    assert_eq!(lift.car_door_status().len(), 2);
    assert_eq!(lift.landing_door_status().len(), 2);
}

#[test]
fn lift_door_array_writes_refuse_bad_values_atomically() {
    let mut lift = simulated_lift();
    let car_doors = lift.car_door_status().to_vec();
    let closed = door(DoorStatus::CLOSED);
    // Reserved and oversized door statuses, whole or as one element.
    for raw in [10u32, 1023, 65_536, u32::MAX] {
        for (index, value) in [
            (
                None,
                PropertyValue::List(vec![closed.clone(), PropertyValue::Enumerated(raw)]),
            ),
            (Some(1), PropertyValue::Enumerated(raw)),
        ] {
            assert_value_out_of_range(
                lift.write_property(P::CAR_DOOR_STATUS, index, value, None),
                &format!("Car_Door_Status {index:?} {raw}"),
            );
        }
    }
    for (index, value) in [
        (Some(1), PropertyValue::Unsigned(0)),
        (Some(1), PropertyValue::List(vec![closed.clone()])),
        (
            None,
            PropertyValue::List(vec![closed.clone(), PropertyValue::Unsigned(0)]),
        ),
    ] {
        assert_invalid_data_type(
            lift.write_property(P::CAR_DOOR_STATUS, index, value.clone(), None),
            &format!("Car_Door_Status {index:?} {value:?}"),
        );
    }
    assert_eq!(lift.car_door_status(), car_doors);

    let landing_doors = lift.landing_door_status().to_vec();
    for (value, expected, context) in [
        (
            PropertyValue::Enumerated(0),
            ErrorCode::INVALID_DATA_TYPE,
            "not a frame",
        ),
        (
            frame(&[0x0E, 0x09, 0x01, 0x19, 0x0A, 0x0F]),
            ErrorCode::VALUE_OUT_OF_RANGE,
            "reserved door status 10",
        ),
        (
            frame(&[0x0E, 0x09, 0x01, 0x19, 0x00]),
            ErrorCode::INVALID_DATA_ENCODING,
            "no closing tag",
        ),
        (
            frame(&[0x0E, 0x0A, 0x01, 0x00, 0x19, 0x00, 0x0F]),
            ErrorCode::VALUE_OUT_OF_RANGE,
            "floor 256",
        ),
        (
            frame(&[0x0E, 0x09, 0x01, 0x0F]),
            ErrorCode::INVALID_DATA_ENCODING,
            "floor without door status",
        ),
        (
            frame(&[0x0E, 0x0F, 0x0E, 0x0F]),
            ErrorCode::INVALID_DATA_ENCODING,
            "two frames in one element",
        ),
    ] {
        assert_property_error(
            lift.write_property(P::LANDING_DOOR_STATUS, Some(1), value.clone(), None),
            expected,
            context,
        );
        // The same element inside a whole-array write fails the same way.
        assert_property_error(
            lift.write_property(
                P::LANDING_DOOR_STATUS,
                None,
                PropertyValue::List(vec![frame(&[0x0E, 0x0F]), value]),
                None,
            ),
            expected,
            context,
        );
    }
    assert_eq!(lift.landing_door_status(), landing_doors);
}

#[test]
fn lift_door_simulation_ends_when_the_lift_returns_to_service() {
    let mut lift = simulated_lift();
    lift.write_property(P::CAR_DOOR_STATUS, Some(1), door(DoorStatus::OPENED), None)
        .unwrap();
    set_out_of_service(&mut lift, false);
    // The simulated value stays until the application sets another, and
    // writes are refused again.
    assert_eq!(
        lift.car_door_status(),
        [DoorStatus::OPENED, DoorStatus::CLOSED]
    );
    for (property, value) in [
        (P::CAR_DOOR_STATUS, door(DoorStatus::CLOSED)),
        (P::LANDING_DOOR_STATUS, frame(&[0x0E, 0x0F])),
    ] {
        for index in [None, Some(1)] {
            assert_property_error(
                lift.write_property(property, index, value.clone(), None),
                ErrorCode::WRITE_ACCESS_DENIED,
                &format!("{property:?} {index:?} in service"),
            );
        }
    }
    assert_eq!(
        lift.car_door_status(),
        [DoorStatus::OPENED, DoorStatus::CLOSED]
    );
    lift.set_car_door_status(vec![DoorStatus::CLOSED, DoorStatus::CLOSED])
        .unwrap();
    assert_eq!(
        lift.car_door_status(),
        [DoorStatus::CLOSED, DoorStatus::CLOSED]
    );
}
