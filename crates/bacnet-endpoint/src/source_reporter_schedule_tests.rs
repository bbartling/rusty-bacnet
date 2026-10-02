use super::*;
use bacnet_objects::schedule::{CalendarObject, ScheduleObject, ScheduleWrite};
use bacnet_types::calendar::SpecificDate;
use bacnet_types::constructed::{BACnetCalendarEntry, BACnetObjectPropertyReference};
use bacnet_types::primitives::Time;

#[test]
fn source_reporter_forwards_complete_schedule_targets() {
    let refs = vec![
        BACnetObjectPropertyReference::new(oid(ObjectType::ANALOG_OUTPUT, 2), 85),
        BACnetObjectPropertyReference::new_indexed(oid(ObjectType::MULTI_STATE_OUTPUT, 7), 110, 2),
    ];
    let mut schedule =
        ScheduleObject::new(3, "wrapped schedule", PropertyValue::Unsigned(1)).unwrap();
    for reference in &refs {
        schedule.add_object_property_reference(reference.clone());
    }
    schedule
        .write_property(
            PropertyIdentifier::SCHEDULE_DEFAULT,
            None,
            PropertyValue::Unsigned(2),
            None,
        )
        .unwrap();
    let mut object: Box<dyn BACnetObject> = Box::new(schedule);
    let owner = bacnet_objects::database::AuditOwnership::for_source(
        oid(ObjectType::DEVICE, 123),
        selected(),
    );
    source_reporter::install(&mut object, &owner).unwrap();
    // Monday 14 September 2026, noon.
    let today = SpecificDate::new(2026, 9, 14).unwrap();
    let noon = Time {
        hour: 12,
        minute: 0,
        second: 0,
        hundredths: 0,
    };
    let no_calendars = |_: ObjectIdentifier| false;
    assert_eq!(
        object.tick_schedule(today, noon, &no_calendars),
        Some(ScheduleWrite {
            value: PropertyValue::Unsigned(2),
            priority: 16,
            references: refs.clone(),
        })
    );
    assert!(object.tick_schedule(today, noon, &no_calendars).is_none());

    // A Present_Value written out of service is owed through the wrapper.
    for (property, value) in [
        (
            PropertyIdentifier::OUT_OF_SERVICE,
            PropertyValue::Boolean(true),
        ),
        (
            PropertyIdentifier::PRESENT_VALUE,
            PropertyValue::Unsigned(5),
        ),
    ] {
        object.write_property(property, None, value, None).unwrap();
    }
    assert_eq!(
        object.take_simulated_schedule_write(),
        Some(ScheduleWrite {
            value: PropertyValue::Unsigned(5),
            priority: 16,
            references: refs,
        })
    );
    assert!(object.take_simulated_schedule_write().is_none());
}

#[test]
fn source_reporter_forwards_calendar_state() {
    let mut calendar = CalendarObject::new(4, "wrapped calendar").unwrap();
    calendar
        .add_date_entry(BACnetCalendarEntry::Date(
            SpecificDate::new(2026, 12, 25).unwrap().to_date(),
        ))
        .unwrap();
    let mut object: Box<dyn BACnetObject> = Box::new(calendar);
    let owner = bacnet_objects::database::AuditOwnership::for_source(
        oid(ObjectType::DEVICE, 123),
        selected(),
    );
    source_reporter::install(&mut object, &owner).unwrap();
    for (day, expected) in [(25, true), (24, false)] {
        let day = SpecificDate::new(2026, 12, day).unwrap();
        assert_eq!(object.calendar_state_internal(day), Some(expected));
    }
}
