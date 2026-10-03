//! SourceReporter forwards a Command object's run hooks (#1150) instead of
//! inheriting the trait defaults, which would leave a wrapped Command busy.
use super::*;
use bacnet_objects::command::CommandObject;
use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};

#[test]
fn command_run_hooks_and_property_cov_admission_survive_wrapping() {
    let mut command = CommandObject::new(1, "CMD-1").unwrap();
    command
        .set_action(vec![BACnetActionList {
            commands: vec![BACnetActionCommand {
                device_identifier: None,
                object_identifier: oid(ObjectType::ANALOG_VALUE, 1),
                property_identifier: PropertyIdentifier::PRESENT_VALUE,
                property_array_index: None,
                property_value: PropertyValue::Real(1.0),
                priority: None,
                post_delay: None,
                quit_on_failure: false,
                write_successful: false,
            }],
        }])
        .unwrap();
    let mut object: Box<dyn BACnetObject> = Box::new(command);
    let owner = bacnet_objects::database::AuditOwnership::for_source(
        oid(ObjectType::DEVICE, 123),
        selected(),
    );
    source_reporter::install(&mut object, &owner).unwrap();
    assert!(object.supports_subscribe_cov_property());

    object
        .write_property(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Unsigned(1),
            None,
        )
        .unwrap();
    let run = object.take_command_run_internal().unwrap();
    assert_eq!(object.command_generation_internal(), Some(run.generation));
    assert!(object.record_command_write_internal(run.generation, 0, true));
    assert!(object.complete_command_run_internal(run.generation, true));
    for (property, expected) in [
        (PropertyIdentifier::IN_PROCESS, false),
        (PropertyIdentifier::ALL_WRITES_SUCCESSFUL, true),
    ] {
        assert_eq!(
            object.read_property(property, None).unwrap(),
            PropertyValue::Boolean(expected),
            "{property:?}"
        );
    }
}
