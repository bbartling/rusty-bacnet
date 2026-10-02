//! Lift Car_Moving_Direction is a BACnetLiftCarDirection (Clause 12.59,
//! Table 12-77; #998): the six named values and the proprietary range
//! 1024..=65535 (Clause 23.1, Table 23-1) are accepted, and the reserved
//! range 6..=1023 and anything above 65535 are refused.

use super::super::*;
use super::{assert_invalid_data_type, assert_value_out_of_range};
use bacnet_types::enums::LiftCarDirection;

const CMD: PropertyIdentifier = PropertyIdentifier::CAR_MOVING_DIRECTION;

fn write(lift: &mut LiftObject, raw: u32) -> Result<(), Error> {
    lift.write_property(CMD, None, PropertyValue::Enumerated(raw), None)
}

fn read(lift: &LiftObject) -> PropertyValue {
    lift.read_property(CMD, None).unwrap()
}

#[test]
fn lift_car_moving_direction_is_typed_and_starts_stopped() {
    let lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    assert_eq!(lift.car_moving_direction, LiftCarDirection::STOPPED);
    // STOPPED is 2 on the wire; 1 is NONE.
    assert_eq!(read(&lift), PropertyValue::Enumerated(2));
}

#[test]
fn lift_car_moving_direction_accepts_every_named_value() {
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    assert_eq!(LiftCarDirection::ALL_NAMED.len(), 6);
    for &(name, direction) in LiftCarDirection::ALL_NAMED {
        write(&mut lift, direction.to_raw())
            .unwrap_or_else(|e| panic!("named direction {name} must be accepted: {e:?}"));
        assert_eq!(lift.car_moving_direction, direction, "{name}");
        assert_eq!(read(&lift), PropertyValue::Enumerated(direction.to_raw()));
    }
    assert_eq!(lift.car_moving_direction, LiftCarDirection::UP_AND_DOWN);
}

#[test]
fn lift_car_moving_direction_keeps_proprietary_values() {
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    for raw in [1024u32, 40_000, 65_535] {
        write(&mut lift, raw)
            .unwrap_or_else(|e| panic!("proprietary raw {raw} must be accepted: {e:?}"));
        assert_eq!(read(&lift), PropertyValue::Enumerated(raw), "{raw}");
    }
}

#[test]
fn lift_car_moving_direction_refuses_reserved_values_atomically() {
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    write(&mut lift, LiftCarDirection::DOWN.to_raw()).unwrap();
    for raw in [6u32, 512, 1023] {
        assert_value_out_of_range(write(&mut lift, raw), &format!("reserved raw {raw}"));
        assert_eq!(lift.car_moving_direction, LiftCarDirection::DOWN, "{raw}");
    }
}

#[test]
fn lift_car_moving_direction_refuses_values_above_65535_atomically() {
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    write(&mut lift, 1024).unwrap();
    for raw in [65_536u32, u32::MAX] {
        assert_value_out_of_range(write(&mut lift, raw), &format!("oversized raw {raw}"));
        assert_eq!(read(&lift), PropertyValue::Enumerated(1024), "{raw}");
    }
}

#[test]
fn lift_car_moving_direction_refuses_wrong_datatypes_atomically() {
    let mut lift = LiftObject::new(1, "LIFT-1", 3).unwrap();
    write(&mut lift, LiftCarDirection::UP.to_raw()).unwrap();
    for value in [PropertyValue::Unsigned(4), PropertyValue::Real(4.0)] {
        assert_invalid_data_type(
            lift.write_property(CMD, None, value.clone(), None),
            &format!("{value:?}"),
        );
        assert_eq!(lift.car_moving_direction, LiftCarDirection::UP);
    }
}
