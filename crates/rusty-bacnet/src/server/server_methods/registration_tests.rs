use super::*;
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::ObjectIdentifier;

#[test]
fn python_staging_boundary_maps_typed_tuples_and_local_references_exactly() {
    let target = ObjectIdentifier::new(ObjectType::BINARY_OUTPUT, 7).unwrap();
    let config = staging_config(
        5.0,
        0.0,
        62,
        8,
        vec![(10.0, vec![false], 1.0), (20.0, vec![true], 1.0)],
        vec![PyObjectIdentifier::from_rust(target)],
        Some(vec!["Off".into(), "On".into()]),
    );

    assert_eq!(config.present_value, 5.0);
    assert_eq!(config.stages[1].values, vec![true]);
    assert_eq!(config.target_references[0].device_identifier, None);
    assert_eq!(config.target_references[0].object_identifier, target);
    assert_eq!(config.stage_names.unwrap(), vec!["Off", "On"]);
}

#[test]
fn elevator_group_machine_room_id_accepts_only_positive_integer_value() {
    use bacnet_objects::traits::BACnetObject;
    use bacnet_types::enums::PropertyIdentifier;
    use bacnet_types::primitives::PropertyValue;

    let room = ObjectIdentifier::new(ObjectType::POSITIVE_INTEGER_VALUE, 5).unwrap();
    let obj = elevator_group(1, "EG", Some(room)).unwrap();
    assert_eq!(
        obj.read_property(PropertyIdentifier::MACHINE_ROOM_ID, None)
            .unwrap(),
        PropertyValue::ObjectIdentifier(room)
    );

    let wrong = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 5).unwrap();
    assert!(elevator_group(1, "EG", Some(wrong)).is_err());
    assert!(elevator_group(1, "EG", None).is_ok());
}

#[test]
fn command_builder_applies_action_then_action_text_through_the_object_setters() {
    use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};
    use bacnet_types::enums::PropertyIdentifier;
    use bacnet_types::primitives::PropertyValue;

    let write = |priority| BACnetActionCommand {
        device_identifier: None,
        object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_OUTPUT, 1).unwrap(),
        property_identifier: PropertyIdentifier::PRESENT_VALUE,
        property_array_index: None,
        property_value: PropertyValue::Real(50.0),
        priority: Some(priority),
        post_delay: None,
        quit_on_failure: false,
        write_successful: false,
    };
    let lists = |priority| {
        vec![
            BACnetActionList {
                commands: vec![write(priority)],
            },
            BACnetActionList::default(),
        ]
    };
    let texts = || Some(vec!["Occupied".to_string(), "Idle".to_string()]);
    let obj = command(1, "CMD-1", Some(lists(8)), texts()).unwrap();
    assert_eq!(
        obj.read_property(PropertyIdentifier::ACTION, Some(0))
            .unwrap(),
        PropertyValue::Unsigned(2)
    );
    assert_eq!(
        obj.read_property(PropertyIdentifier::ACTION_TEXT, Some(2))
            .unwrap(),
        PropertyValue::CharacterString("Idle".into())
    );
    // The setters refuse what BACnet doesn't allow.
    assert!(command(1, "CMD-1", Some(lists(17)), None).is_err());
    assert!(command(1, "CMD-1", Some(lists(8)), Some(vec!["Occupied".into()])).is_err());
    assert!(command(1, "CMD-1", None, texts()).is_err());
    assert!(command(1, "CMD-1", None, None).is_ok());
}
