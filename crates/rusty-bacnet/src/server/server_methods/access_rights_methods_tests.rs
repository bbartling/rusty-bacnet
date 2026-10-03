use super::*;
use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, BACnetDeviceObjectReference};
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn business_hours() -> BACnetAccessRule {
    BACnetAccessRule::new(
        Some(BACnetDeviceObjectPropertyReference::new_local(
            oid(ObjectType::SCHEDULE, 1),
            PropertyIdentifier::PRESENT_VALUE.to_raw(),
        )),
        Some(oid(ObjectType::ACCESS_POINT, 2).into()),
        true,
    )
}

#[test]
fn python_access_rules_reach_both_arrays() {
    let lockdown = BACnetAccessRule::new(
        None,
        Some(BACnetDeviceObjectReference::from(oid(
            ObjectType::ACCESS_ZONE,
            3,
        ))),
        true,
    );
    let rights = access_rights(
        1,
        "AR-1",
        Some(vec![business_hours()]),
        Some(vec![lockdown.clone()]),
        true,
    )
    .unwrap();
    assert_eq!(rights.positive_access_rules(), [business_hours()]);
    assert_eq!(rights.negative_access_rules(), [lockdown]);
    assert_eq!(
        rights
            .read_property(PropertyIdentifier::POSITIVE_ACCESS_RULES, Some(0))
            .unwrap(),
        PropertyValue::Unsigned(1)
    );

    // A location naming an Access Door is the setter's refusal.
    let door = BACnetAccessRule::new(None, Some(oid(ObjectType::ACCESS_DOOR, 2).into()), true);
    for (positive, negative) in [(Some(vec![door.clone()]), None), (None, Some(vec![door]))] {
        let refused = access_rights(2, "AR-2", positive, negative, true)
            .err()
            .unwrap();
        assert!(
            matches!(refused, Error::Protocol { class, code }
                if class == ErrorClass::PROPERTY.to_raw() as u32
                    && code == ErrorCode::VALUE_OUT_OF_RANGE.to_raw() as u32),
            "{refused:?}"
        );
    }

    // Omitted arguments keep both arrays empty.
    let bare = access_rights(3, "AR-3", None, None, true).unwrap();
    assert!(bare.positive_access_rules().is_empty());
    assert!(bare.negative_access_rules().is_empty());
}

#[test]
fn python_enable_reaches_the_enable_row() {
    assert!(rights_enable(true));
    assert!(!rights_enable(false));
    let disabled = access_rights(4, "AR-4", Some(vec![business_hours()]), None, false).unwrap();
    assert_eq!(
        disabled
            .read_property(PropertyIdentifier::LOG_ENABLE, None)
            .unwrap(),
        PropertyValue::Boolean(false)
    );
    // The rules keep their own enable flags.
    assert_eq!(disabled.positive_access_rules(), [business_hours()]);
}

fn rights_enable(enable: bool) -> bool {
    access_rights(5, "AR-5", None, None, enable)
        .unwrap()
        .enable()
}
