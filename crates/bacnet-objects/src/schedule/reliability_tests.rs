//! The Schedule's Reliability (#1056): CONFIGURATION_ERROR while the non-NULL
//! values of Weekly_Schedule, Exception_Schedule and Schedule_Default are not
//! all of one datatype, from the setters and from network writes alike.

use super::*;
use crate::traits::ReliabilityEvaluation;
use bacnet_encoding::constructed::encode_special_event;
use bacnet_types::calendar::SpecificDate;
use bacnet_types::constructed::SpecialEventPeriod;

type P = PropertyIdentifier;

fn at(hour: u8, minute: u8) -> Time {
    Time {
        hour,
        minute,
        second: 0,
        hundredths: 0,
    }
}

fn tv(hour: u8, value: PropertyValue) -> BACnetTimeValue {
    BACnetTimeValue {
        time: at(hour, 0),
        value,
    }
}

fn holiday(value: PropertyValue) -> BACnetSpecialEvent {
    BACnetSpecialEvent {
        period: SpecialEventPeriod::CalendarReference(
            ObjectIdentifier::new(ObjectType::CALENDAR, 1).unwrap(),
        ),
        list_of_time_values: vec![tv(0, value)],
        event_priority: 4,
    }
}

fn reliability(sched: &ScheduleObject) -> Reliability {
    match sched.read_property(P::RELIABILITY, None).unwrap() {
        PropertyValue::Enumerated(raw) => Reliability::from_raw(raw),
        other => panic!("Reliability reads as {other:?}"),
    }
}

/// Status_Flags as `[in_alarm, fault, overridden, out_of_service]`.
fn flags(sched: &ScheduleObject) -> [bool; 4] {
    let PropertyValue::BitString { data, .. } = sched.read_property(P::STATUS_FLAGS, None).unwrap()
    else {
        panic!("Status_Flags reads as a bit string");
    };
    let octet = data.first().copied().unwrap_or(0);
    [0x80, 0x40, 0x20, 0x10].map(|bit| octet & bit != 0)
}

fn assert_fault(sched: &ScheduleObject, fault: bool, what: &str) {
    let expected = if fault {
        Reliability::CONFIGURATION_ERROR
    } else {
        Reliability::NO_FAULT_DETECTED
    };
    assert_eq!(reliability(sched), expected, "{what}");
    assert_eq!(flags(sched)[1], fault, "{what}: Status_Flags FAULT");
}

#[test]
fn mixed_datatypes_from_the_setters_are_a_configuration_error() {
    let mut sched = ScheduleObject::new(1, "SCHED-1", PropertyValue::Real(10.0)).unwrap();
    assert_fault(&sched, false, "a lone Real default");

    sched
        .set_weekly_schedule(0, vec![tv(8, PropertyValue::Real(21.0))])
        .unwrap();
    assert_fault(&sched, false, "Real weekly entries");

    // A Boolean in Tuesday's list disagrees with the Reals.
    sched
        .set_weekly_schedule(1, vec![tv(8, PropertyValue::Boolean(true))])
        .unwrap();
    assert_fault(&sched, true, "a Boolean among Reals");

    // Replacing it with a Real clears the fault.
    sched
        .set_weekly_schedule(1, vec![tv(8, PropertyValue::Real(19.0))])
        .unwrap();
    assert_fault(&sched, false, "Reals again");

    // An exception's values count too, and so do numeric datatypes that
    // differ: an Unsigned is not a Real.
    sched
        .add_exception(holiday(PropertyValue::Unsigned(19)))
        .unwrap();
    assert_fault(&sched, true, "an Unsigned exception value");
}

#[test]
fn nulls_and_an_empty_schedule_never_disagree() {
    let mut sched = ScheduleObject::new(1, "SCHED-1", PropertyValue::Null).unwrap();
    assert_fault(&sched, false, "NULL default alone");
    sched
        .set_weekly_schedule(
            0,
            vec![
                tv(8, PropertyValue::Enumerated(1)),
                tv(17, PropertyValue::Null),
            ],
        )
        .unwrap();
    sched.add_exception(holiday(PropertyValue::Null)).unwrap();
    sched
        .add_exception(holiday(PropertyValue::Enumerated(0)))
        .unwrap();
    assert_fault(&sched, false, "Enumerated values among NULLs");
    sched
        .write_property(
            P::SCHEDULE_DEFAULT,
            None,
            PropertyValue::CharacterString("off".into()),
            None,
        )
        .unwrap();
    assert_fault(&sched, true, "a CharacterString default");
    sched
        .write_property(P::SCHEDULE_DEFAULT, None, PropertyValue::Null, None)
        .unwrap();
    assert_fault(&sched, false, "NULL default again");
}

#[test]
fn network_writes_re_evaluate_reliability() {
    let mut sched = ScheduleObject::new(1, "SCHED-1", PropertyValue::Real(10.0)).unwrap();
    // A whole Weekly_Schedule write whose Monday holds a Boolean TRUE.
    let mut weekly = vec![0x0E, 0xB4, 8, 0, 0, 0, 0x11, 0x0F];
    weekly.extend([0x0E, 0x0F].repeat(6));
    sched
        .write_property(
            P::WEEKLY_SCHEDULE,
            None,
            PropertyValue::ApplicationData(weekly),
            None,
        )
        .unwrap();
    assert_fault(&sched, true, "Boolean weekly value, Real default");

    // Schedule_Default written as a Boolean makes them agree.
    sched
        .write_property(
            P::SCHEDULE_DEFAULT,
            None,
            PropertyValue::Boolean(false),
            None,
        )
        .unwrap();
    assert_fault(&sched, false, "Boolean default");

    // An exception written at index 1 after growing the array to one event.
    let mut event = BytesMut::new();
    encode_special_event(&mut event, &holiday(PropertyValue::Real(5.0))).unwrap();
    sched
        .write_property(
            P::EXCEPTION_SCHEDULE,
            Some(0),
            PropertyValue::Unsigned(1),
            None,
        )
        .unwrap();
    assert_fault(&sched, false, "an empty appended event");
    sched
        .write_property(
            P::EXCEPTION_SCHEDULE,
            Some(1),
            PropertyValue::ApplicationData(event.to_vec()),
            None,
        )
        .unwrap();
    assert_fault(&sched, true, "a Real exception value");

    // Truncating the array away removes the disagreeing value.
    sched
        .write_property(
            P::EXCEPTION_SCHEDULE,
            Some(0),
            PropertyValue::Unsigned(0),
            None,
        )
        .unwrap();
    assert_fault(&sched, false, "exceptions truncated");

    // A refused write changes neither the contents nor Reliability.
    let duplicate = vec![
        0x0E, 0xB4, 8, 0, 0, 0, 0x44, 0x41, 0xA8, 0, 0, 0xB4, 8, 0, 0, 0, 0x10, 0x0F,
    ];
    assert!(sched
        .write_property(
            P::WEEKLY_SCHEDULE,
            Some(1),
            PropertyValue::ApplicationData(duplicate),
            None,
        )
        .is_err());
    assert_fault(&sched, false, "refused write");
}

#[test]
fn a_reliability_applied_by_the_application_is_left_alone() {
    let mut sched = ScheduleObject::new(1, "SCHED-1", PropertyValue::Real(10.0)).unwrap();
    sched
        .set_reliability_internal(Reliability::UNRELIABLE_OTHER)
        .unwrap();
    sched
        .set_weekly_schedule(0, vec![tv(8, PropertyValue::Boolean(true))])
        .unwrap();
    assert_eq!(reliability(&sched), Reliability::UNRELIABLE_OTHER);
    assert_eq!(
        sched.evaluate_reliability_internal().unwrap(),
        ReliabilityEvaluation::Unchanged
    );

    // Once the application clears it, the periodic pass raises the fault.
    sched
        .set_reliability_internal(Reliability::NO_FAULT_DETECTED)
        .unwrap();
    assert_eq!(
        sched.evaluate_reliability_internal().unwrap(),
        ReliabilityEvaluation::Changed {
            old_reliability: Reliability::NO_FAULT_DETECTED,
            new_reliability: Reliability::CONFIGURATION_ERROR,
        }
    );
    assert_eq!(
        sched.evaluate_reliability_internal().unwrap(),
        ReliabilityEvaluation::Unchanged
    );
    // And clears the fault it raised once the contents agree.
    sched.set_weekly_schedule(0, vec![]).unwrap();
    assert_fault(&sched, false, "contents agree");
}

#[test]
fn out_of_service_keeps_the_simulated_reliability_until_return() {
    let mut sched = ScheduleObject::new(1, "SCHED-1", PropertyValue::Real(10.0)).unwrap();
    sched
        .write_property(P::OUT_OF_SERVICE, None, PropertyValue::Boolean(true), None)
        .unwrap();
    sched
        .set_weekly_schedule(0, vec![tv(8, PropertyValue::Boolean(true))])
        .unwrap();
    assert_eq!(reliability(&sched), Reliability::NO_FAULT_DETECTED);
    assert_eq!(
        sched.evaluate_reliability_internal().unwrap(),
        ReliabilityEvaluation::Unchanged
    );
    sched
        .write_property(
            P::RELIABILITY,
            None,
            PropertyValue::Enumerated(Reliability::OVER_RANGE.to_raw()),
            None,
        )
        .unwrap();
    assert_eq!(reliability(&sched), Reliability::OVER_RANGE);

    // Back in service, the saved value is restored and checked again.
    sched
        .write_property(P::OUT_OF_SERVICE, None, PropertyValue::Boolean(false), None)
        .unwrap();
    assert_fault(&sched, true, "back in service with mixed values");
    assert_eq!(flags(&sched), [false, true, false, false]);
}

#[test]
fn a_misconfigured_schedule_still_writes_its_references() {
    let mut sched = ScheduleObject::new(1, "SCHED-1", PropertyValue::Real(10.0)).unwrap();
    let target = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 2).unwrap();
    sched.add_object_property_reference(BACnetObjectPropertyReference::new(
        target,
        PropertyIdentifier::PRESENT_VALUE.to_raw(),
    ));
    sched
        .set_weekly_schedule(
            0,
            vec![
                tv(8, PropertyValue::Real(21.0)),
                tv(17, PropertyValue::Boolean(false)),
            ],
        )
        .unwrap();
    assert_fault(&sched, true, "Boolean among Reals");
    let monday = SpecificDate::new(2026, 9, 14).unwrap();
    let no_calendars = |_| false;
    let write = sched
        .tick_schedule(monday, at(9, 0), &no_calendars)
        .expect("the first pass in the period writes");
    assert_eq!(write.value, PropertyValue::Real(21.0));
    assert_eq!(write.references.len(), 1);
    let write = sched
        .tick_schedule(monday, at(17, 0), &no_calendars)
        .expect("a change writes");
    assert_eq!(write.value, PropertyValue::Boolean(false));
}
