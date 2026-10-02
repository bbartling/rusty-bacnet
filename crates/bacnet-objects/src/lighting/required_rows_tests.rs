//! Lighting rows Tables 12-64 and 12-69 require that the objects used to lack
//! (#1092): Default_Ramp_Rate and Default_Step_Increment on Lighting Output,
//! and Current_Command_Priority on both objects.

use super::*;
use bacnet_types::enums::{ErrorClass, ErrorCode};
use std::time::Duration;

fn assert_error<T: std::fmt::Debug>(result: Result<T, Error>, expected: ErrorCode) {
    match result {
        Err(Error::Protocol { class, code }) => {
            assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
            assert_eq!(code, expected.to_raw() as u32, "expected {expected:?}");
        }
        other => panic!("expected PROPERTY/{expected:?}, got {other:?}"),
    }
}

fn read(object: &dyn BACnetObject, property: PropertyIdentifier) -> PropertyValue {
    object.read_property(property, None).unwrap()
}

fn command(object: &mut dyn BACnetObject, value: PropertyValue, priority: u8) {
    object
        .write_property(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            value,
            Some(priority),
        )
        .unwrap();
}

#[test]
fn lighting_output_default_ramp_rate_and_step_increment_take_writes_within_their_range() {
    for property in [
        PropertyIdentifier::DEFAULT_RAMP_RATE,
        PropertyIdentifier::DEFAULT_STEP_INCREMENT,
    ] {
        let mut lo = LightingOutputObject::new(1, "LO-1").unwrap();
        assert!(lo.is_writable_property(property));
        // Both ends of 0.1..=100.0 are allowed.
        for value in [0.1, 42.5, 100.0] {
            lo.write_property(property, None, PropertyValue::Real(value), None)
                .unwrap();
            assert_eq!(
                read(&lo, property),
                PropertyValue::Real(value),
                "{property:?}"
            );
        }
        // Outside the range, or not a number, the value stays at 100.0.
        for value in [0.0, 0.09, 100.01, -1.0, f32::NAN, f32::INFINITY] {
            assert_error(
                lo.write_property(property, None, PropertyValue::Real(value), None),
                ErrorCode::VALUE_OUT_OF_RANGE,
            );
            assert_eq!(read(&lo, property), PropertyValue::Real(100.0), "{value}");
        }
        for value in [PropertyValue::Unsigned(5), PropertyValue::Null] {
            assert_error(
                lo.write_property(property, None, value, None),
                ErrorCode::INVALID_DATA_TYPE,
            );
        }
        assert_eq!(read(&lo, property), PropertyValue::Real(100.0));
    }
}

#[test]
fn lighting_output_default_ramp_rate_and_step_increment_setters_share_the_range() {
    let mut lo = LightingOutputObject::new(1, "LO-1").unwrap();
    lo.set_default_ramp_rate(12.5).unwrap();
    lo.set_default_step_increment(0.5).unwrap();
    for value in [0.0, 100.5, f32::NAN] {
        assert_error(
            lo.set_default_ramp_rate(value),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_error(
            lo.set_default_step_increment(value),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
    }
    assert_eq!(
        read(&lo, PropertyIdentifier::DEFAULT_RAMP_RATE),
        PropertyValue::Real(12.5)
    );
    assert_eq!(
        read(&lo, PropertyIdentifier::DEFAULT_STEP_INCREMENT),
        PropertyValue::Real(0.5)
    );
}

/// Command and relinquish slots and check Current_Command_Priority names the
/// slot Present_Value comes from, or is Null on Relinquish_Default.
fn assert_current_command_priority_tracks_commands(
    object: &mut dyn BACnetObject,
    on: PropertyValue,
) {
    let ccp = PropertyIdentifier::CURRENT_COMMAND_PRIORITY;
    assert_eq!(read(object, ccp), PropertyValue::Null);
    command(object, on.clone(), 8);
    assert_eq!(read(object, ccp), PropertyValue::Unsigned(8));
    command(object, on.clone(), 16);
    assert_eq!(read(object, ccp), PropertyValue::Unsigned(8));
    command(object, on, 3);
    assert_eq!(read(object, ccp), PropertyValue::Unsigned(3));
    command(object, PropertyValue::Null, 3);
    assert_eq!(read(object, ccp), PropertyValue::Unsigned(8));
    command(object, PropertyValue::Null, 8);
    assert_eq!(read(object, ccp), PropertyValue::Unsigned(16));
    command(object, PropertyValue::Null, 16);
    assert_eq!(read(object, ccp), PropertyValue::Null);
    // Derived from Priority_Array, so no write reaches it.
    assert!(!object.is_writable_property(ccp));
    for value in [PropertyValue::Unsigned(8), PropertyValue::Null] {
        assert_error(
            object.write_property(ccp, None, value, None),
            ErrorCode::WRITE_ACCESS_DENIED,
        );
    }
    assert_eq!(read(object, ccp), PropertyValue::Null);
}

#[test]
fn lighting_output_current_command_priority_names_the_winning_slot() {
    let mut lo = LightingOutputObject::new(1, "LO-1").unwrap();
    assert_current_command_priority_tracks_commands(&mut lo, PropertyValue::Real(60.0));
}

#[test]
fn binary_lighting_output_current_command_priority_names_the_winning_slot() {
    let mut blo = BinaryLightingOutputObject::new(1, "BLO-1").unwrap();
    assert_current_command_priority_tracks_commands(&mut blo, PropertyValue::Enumerated(1));
}

#[test]
fn binary_lighting_output_current_command_priority_holds_through_egress() {
    let mut blo = BinaryLightingOutputObject::new(1, "BLO-1").unwrap();
    blo.write_property(
        PropertyIdentifier::BLINK_WARN_ENABLE,
        None,
        PropertyValue::Boolean(true),
        None,
    )
    .unwrap();
    blo.write_property(
        PropertyIdentifier::EGRESS_TIME,
        None,
        PropertyValue::Unsigned(5),
        None,
    )
    .unwrap();
    command(&mut blo, PropertyValue::Enumerated(1), 8);
    // WARN_RELINQUISH keeps the light on at priority 8 until egress ends.
    command(&mut blo, PropertyValue::Enumerated(4), 8);
    let ccp = PropertyIdentifier::CURRENT_COMMAND_PRIORITY;
    assert_eq!(
        read(&blo, PropertyIdentifier::EGRESS_ACTIVE),
        PropertyValue::Boolean(true)
    );
    assert_eq!(read(&blo, ccp), PropertyValue::Unsigned(8));
    assert!(blo.advance_time_internal(Duration::from_secs(5)));
    assert_eq!(read(&blo, ccp), PropertyValue::Null);
}
