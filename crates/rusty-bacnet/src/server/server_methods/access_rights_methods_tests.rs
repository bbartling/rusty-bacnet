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
        None,
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
        let refused = access_rights(2, "AR-2", None, positive, negative, true)
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
    let bare = access_rights(3, "AR-3", None, None, None, true).unwrap();
    assert!(bare.positive_access_rules().is_empty());
    assert!(bare.negative_access_rules().is_empty());
}

#[test]
fn python_enable_reaches_the_enable_row() {
    assert!(rights_enable(true));
    assert!(!rights_enable(false));
    let disabled =
        access_rights(4, "AR-4", None, Some(vec![business_hours()]), None, false).unwrap();
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
    access_rights(5, "AR-5", None, None, None, enable)
        .unwrap()
        .enable()
}

#[test]
fn python_storage_path_keeps_written_values_over_the_keywords() {
    let directory = std::env::temp_dir().join(format!(
        "rusty-bacnet-python-access-rights-{}",
        std::process::id()
    ));
    let path = directory.join("rights-6");
    let path = path.to_str().unwrap();
    let anywhere = BACnetAccessRule::new(None, None, false);
    // First start: nothing saved, so the keywords apply.
    let mut rights = access_rights(6, "AR-6", Some(path), None, None, true).unwrap();
    assert!(rights.positive_access_rules().is_empty());
    // A peer writes Positive_Access_Rules and Enable; both are saved.
    let mut octets = bytes::BytesMut::new();
    bacnet_encoding::constructed::encode_access_rule(&mut octets, &anywhere);
    rights
        .write_property(
            PropertyIdentifier::POSITIVE_ACCESS_RULES,
            None,
            PropertyValue::ApplicationData(octets.to_vec()),
            None,
        )
        .unwrap();
    rights
        .write_property(
            PropertyIdentifier::LOG_ENABLE,
            None,
            PropertyValue::Boolean(false),
            None,
        )
        .unwrap();
    drop(rights);
    // Next start: the written values win over the keywords; the array no
    // write set still takes its keyword.
    let rebuilt = access_rights(
        6,
        "AR-6",
        Some(path),
        Some(vec![business_hours()]),
        Some(vec![business_hours()]),
        true,
    )
    .unwrap();
    assert_eq!(rebuilt.positive_access_rules(), [anywhere]);
    assert_eq!(rebuilt.negative_access_rules(), [business_hours()]);
    assert!(!rebuilt.enable());
    // Another object can't load this object's file.
    assert!(access_rights(7, "AR-7", Some(path), None, None, true).is_err());
    let _ = std::fs::remove_dir_all(directory);
}
