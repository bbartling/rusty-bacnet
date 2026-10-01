//! Status_Flags is computed from Reliability, Out_Of_Service and Event_State
//! on Loop, Schedule, Calendar, Trend Log and Trend Log Multiple (#978).
//!
//! These objects used to return a Status_Flags fixed at construction, so FAULT
//! and OUT_OF_SERVICE never moved. Each step below checks the four bits against
//! the object's own Reliability, Out_Of_Service and Event_State readbacks, then
//! pins the expected bits outright.

use crate::loop_obj::LoopObject;
use crate::schedule::{CalendarObject, ScheduleObject};
use crate::traits::BACnetObject;
use crate::trend::{TrendLogMultipleObject, TrendLogObject};
use bacnet_types::enums::{EventState, PropertyIdentifier, Reliability};
use bacnet_types::primitives::{PropertyValue, StatusFlags};

fn read(object: &dyn BACnetObject, property: PropertyIdentifier) -> PropertyValue {
    object
        .read_property(property, None)
        .expect("test property must be readable")
}

fn status_flags(object: &dyn BACnetObject) -> StatusFlags {
    match read(object, PropertyIdentifier::STATUS_FLAGS) {
        PropertyValue::BitString {
            unused_bits: 4,
            data,
        } if data.len() == 1 => StatusFlags::from_bits_truncate(data[0] >> 4),
        other => panic!("Status_Flags must be a four-bit bit string, got {other:?}"),
    }
}

/// Assert the flags agree with the object's readable state, then that they
/// equal `expected`.
fn assert_flags(object: &dyn BACnetObject, expected: StatusFlags) {
    let flags = status_flags(object);
    let reliability = match read(object, PropertyIdentifier::RELIABILITY) {
        PropertyValue::Enumerated(raw) => Reliability::from_raw(raw),
        other => panic!("Reliability must be Enumerated, got {other:?}"),
    };
    assert_eq!(
        flags.contains(StatusFlags::FAULT),
        reliability != Reliability::NO_FAULT_DETECTED,
        "FAULT must follow Reliability ({reliability})"
    );
    assert_eq!(
        flags.contains(StatusFlags::OUT_OF_SERVICE),
        read(object, PropertyIdentifier::OUT_OF_SERVICE) == PropertyValue::Boolean(true),
        "OUT_OF_SERVICE must follow Out_Of_Service"
    );
    assert_eq!(
        flags.contains(StatusFlags::IN_ALARM),
        read(object, PropertyIdentifier::EVENT_STATE)
            != PropertyValue::Enumerated(EventState::NORMAL.to_raw()),
        "IN_ALARM must follow Event_State"
    );
    assert_eq!(flags, expected);
}

fn write(object: &mut dyn BACnetObject, property: PropertyIdentifier, value: PropertyValue) {
    object
        .write_property(property, None, value, None)
        .expect("test write must succeed");
}

fn set_out_of_service(object: &mut dyn BACnetObject, value: bool) {
    write(
        object,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(value),
    );
}

/// Loop and Schedule own Reliability in service and let a client simulate it
/// while Out_Of_Service is TRUE; the evaluated value comes back on return.
fn assert_simulation_and_evaluation_drive_flags(object: &mut dyn BACnetObject) {
    assert_flags(object, StatusFlags::empty());

    object
        .set_reliability_internal(Reliability::CONFIGURATION_ERROR)
        .unwrap();
    assert_flags(object, StatusFlags::FAULT);

    set_out_of_service(object, true);
    assert_flags(object, StatusFlags::FAULT | StatusFlags::OUT_OF_SERVICE);

    write(
        object,
        PropertyIdentifier::RELIABILITY,
        PropertyValue::Enumerated(Reliability::NO_FAULT_DETECTED.to_raw()),
    );
    assert_flags(object, StatusFlags::OUT_OF_SERVICE);

    write(
        object,
        PropertyIdentifier::RELIABILITY,
        PropertyValue::Enumerated(Reliability::OPEN_LOOP.to_raw()),
    );
    assert_flags(object, StatusFlags::FAULT | StatusFlags::OUT_OF_SERVICE);

    // Leaving Out_Of_Service restores the evaluated CONFIGURATION_ERROR.
    set_out_of_service(object, false);
    assert_flags(object, StatusFlags::FAULT);

    object
        .set_reliability_internal(Reliability::NO_FAULT_DETECTED)
        .unwrap();
    assert_flags(object, StatusFlags::empty());
}

#[test]
fn loop_status_flags_follow_reliability_and_out_of_service() {
    assert_simulation_and_evaluation_drive_flags(&mut LoopObject::new(1, "LOOP-1", 62).unwrap());
}

#[test]
fn schedule_status_flags_follow_reliability_and_out_of_service() {
    assert_simulation_and_evaluation_drive_flags(
        &mut ScheduleObject::new(1, "SCHED-1", PropertyValue::Real(0.0)).unwrap(),
    );
}

#[test]
fn trend_log_out_of_service_sets_its_status_flag() {
    let mut log = TrendLogObject::new(1, "TL-1", 10).unwrap();
    assert_flags(&log, StatusFlags::empty());
    set_out_of_service(&mut log, true);
    assert_flags(&log, StatusFlags::OUT_OF_SERVICE);
    set_out_of_service(&mut log, false);
    assert_flags(&log, StatusFlags::empty());
}

#[test]
fn calendar_and_trend_log_multiple_flags_match_their_fixed_state() {
    // Neither object can change Reliability or Out_Of_Service yet, so the
    // computed flags stay clear and agree with those readbacks.
    let calendar = CalendarObject::new(1, "CAL-1").unwrap();
    assert_eq!(status_flags(&calendar), StatusFlags::empty());
    assert_eq!(
        read(&calendar, PropertyIdentifier::OUT_OF_SERVICE),
        PropertyValue::Boolean(false)
    );
    assert_flags(
        &TrendLogMultipleObject::new(1, "TLM-1", 10).unwrap(),
        StatusFlags::empty(),
    );
}
