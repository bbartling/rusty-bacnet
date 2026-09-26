use super::*;
use bacnet_objects::schedule::ScheduleObject;
use bacnet_types::constructed::BACnetObjectPropertyReference;

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
    assert_eq!(
        object.tick_schedule(0, 12, 0),
        Some((PropertyValue::Unsigned(2), refs))
    );
    assert!(object.tick_schedule(0, 12, 0).is_none());
}
