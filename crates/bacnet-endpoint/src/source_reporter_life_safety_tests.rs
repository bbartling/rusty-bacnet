use super::*;
use bacnet_objects::life_safety::LifeSafetyPointObject;
use bacnet_objects::traits::LifeSafetyOperationEffect;
use bacnet_types::enums::{LifeSafetyOperation, LifeSafetyState};

#[test]
fn life_safety_outcome_and_error_forward_without_losing_deltas() {
    let mut point = LifeSafetyPointObject::new(1, "wrapped point").unwrap();
    point.set_operation_expected(LifeSafetyOperation::SILENCE);
    let mut object: Box<dyn BACnetObject> = Box::new(point);
    let owner = bacnet_objects::database::AuditOwnership::for_source(
        oid(ObjectType::DEVICE, 123),
        selected(),
    );
    source_reporter::install(&mut object, &owner).unwrap();
    let outcome = object
        .apply_life_safety_operation(LifeSafetyOperation::SILENCE)
        .unwrap();
    assert_eq!(outcome.effect, LifeSafetyOperationEffect::Applied);
    assert_eq!(
        outcome.changed_properties,
        vec![
            PropertyIdentifier::SILENCED,
            PropertyIdentifier::OPERATION_EXPECTED
        ]
    );
    let before = [
        read(object.as_ref(), PropertyIdentifier::SILENCED),
        read(object.as_ref(), PropertyIdentifier::OPERATION_EXPECTED),
    ];
    assert!(
        matches!(object.apply_life_safety_operation(LifeSafetyOperation::SILENCE), Err(Error::Protocol {class,code}) if class == ErrorClass::OBJECT.to_raw() as u32 && code == ErrorCode::INVALID_OPERATION_IN_THIS_STATE.to_raw() as u32)
    );
    assert_eq!(
        [
            read(object.as_ref(), PropertyIdentifier::SILENCED),
            read(object.as_ref(), PropertyIdentifier::OPERATION_EXPECTED)
        ],
        before
    );
}

#[test]
fn absent_life_safety_capability_remains_explicitly_unsupported() {
    let mut object: Box<dyn BACnetObject> =
        Box::new(bacnet_objects::analog::AnalogInputObject::new(1, "input", 0).unwrap());
    let owner = bacnet_objects::database::AuditOwnership::for_source(
        oid(ObjectType::DEVICE, 123),
        selected(),
    );
    source_reporter::install(&mut object, &owner).unwrap();
    assert!(
        matches!(object.apply_life_safety_operation(LifeSafetyOperation::SILENCE), Err(Error::Protocol {class,code}) if class == ErrorClass::OBJECT.to_raw() as u32 && code == ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.to_raw() as u32)
    );
}

#[test]
fn life_safety_application_values_forward_through_the_wrapper() {
    let mut object: Box<dyn BACnetObject> =
        Box::new(LifeSafetyPointObject::new(1, "wrapped point").unwrap());
    let owner = bacnet_objects::database::AuditOwnership::for_source(
        oid(ObjectType::DEVICE, 123),
        selected(),
    );
    source_reporter::install(&mut object, &owner).unwrap();
    let alarm = PropertyValue::Enumerated(LifeSafetyState::ALARM.to_raw());
    let pre_alarm = PropertyValue::Enumerated(LifeSafetyState::PRE_ALARM.to_raw());
    object.set_present_value_internal(alarm.clone()).unwrap();
    object
        .set_tracking_value_internal(pre_alarm.clone())
        .unwrap();
    assert_eq!(
        read(object.as_ref(), PropertyIdentifier::PRESENT_VALUE),
        alarm
    );
    assert_eq!(
        read(object.as_ref(), PropertyIdentifier::TRACKING_VALUE),
        pre_alarm
    );
    // The wrapped object's range check answers, not the trait default.
    assert!(
        matches!(object.set_tracking_value_internal(PropertyValue::Enumerated(35)), Err(Error::Protocol {class,code}) if class == ErrorClass::PROPERTY.to_raw() as u32 && code == ErrorCode::VALUE_OUT_OF_RANGE.to_raw() as u32)
    );
    assert_eq!(
        read(object.as_ref(), PropertyIdentifier::TRACKING_VALUE),
        pre_alarm
    );
}
