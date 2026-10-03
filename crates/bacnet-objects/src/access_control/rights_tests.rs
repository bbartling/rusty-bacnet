//! Access Rights Positive_Access_Rules and Negative_Access_Rules (#1316):
//! the rules the setters store and refuse, and the arrays as reads serve
//! them.

use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, BACnetDeviceObjectReference};
use bacnet_types::enums::{ErrorClass, ErrorCode, PropertyIdentifier as P};

use super::*;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn assert_property_error<T: std::fmt::Debug>(result: Result<T, Error>, code: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class, code: actual })
            if class == ErrorClass::PROPERTY.to_raw() as u32
                && actual == code.to_raw() as u32),
        "expected PROPERTY / {code:?}, got {result:?}"
    );
}

/// Schedule `instance`'s Present_Value (property 85) in this device.
fn schedule(instance: u32) -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference::new_local(oid(ObjectType::SCHEDULE, instance), 85)
}

fn local(object_type: ObjectType, instance: u32) -> BACnetDeviceObjectReference {
    oid(object_type, instance).into()
}

/// The time range and location a rule names, with SPECIFIED for each given.
fn rule(
    time_range: Option<BACnetDeviceObjectPropertyReference>,
    location: Option<BACnetDeviceObjectReference>,
) -> BACnetAccessRule {
    BACnetAccessRule::new(time_range, location, true)
}

/// A rule's Clause 21 encoding, as one array element reads.
fn element(rule: &BACnetAccessRule) -> PropertyValue {
    let mut buf = BytesMut::new();
    encode_access_rule(&mut buf, rule);
    PropertyValue::ApplicationData(buf.to_vec())
}

#[test]
fn access_rights_rule_arrays_read_whole_and_by_index() {
    let mut rights = AccessRightsObject::new(7, "AR-7").unwrap();
    let business_hours = rule(Some(schedule(1)), Some(local(ObjectType::ACCESS_POINT, 2)));
    let anywhere = BACnetAccessRule::new(None, None, false);
    let lockdown = rule(None, Some(local(ObjectType::ACCESS_ZONE, 3)));
    rights
        .set_positive_access_rules([business_hours.clone(), anywhere.clone()])
        .unwrap();
    rights
        .set_negative_access_rules([lockdown.clone()])
        .unwrap();
    assert_eq!(
        rights.positive_access_rules(),
        [business_hours.clone(), anywhere.clone()]
    );
    assert_eq!(
        rights.negative_access_rules(),
        std::slice::from_ref(&lockdown)
    );

    for (property, rules) in [
        (P::POSITIVE_ACCESS_RULES, vec![business_hours, anywhere]),
        (P::NEGATIVE_ACCESS_RULES, vec![lockdown]),
    ] {
        assert!(rights.is_array_property(property), "{property:?}");
        let elements: Vec<PropertyValue> = rules.iter().map(element).collect();
        assert_eq!(
            rights.read_property(property, None).unwrap(),
            PropertyValue::List(elements.clone())
        );
        assert_eq!(
            rights.read_property(property, Some(0)).unwrap(),
            PropertyValue::Unsigned(rules.len() as u64)
        );
        for (index, element) in elements.into_iter().enumerate() {
            assert_eq!(
                rights
                    .read_property(property, Some(index as u32 + 1))
                    .unwrap(),
                element
            );
        }
        assert_property_error(
            rights.read_property(property, Some(rules.len() as u32 + 1)),
            ErrorCode::INVALID_ARRAY_INDEX,
        );
    }

    // ALWAYS, Schedule 1, ALL with the enable flag clear, in its exact octets.
    assert_eq!(
        rights
            .read_property(P::POSITIVE_ACCESS_RULES, Some(2))
            .unwrap(),
        PropertyValue::ApplicationData(vec![0x09, 0x01, 0x29, 0x01, 0x49, 0x00])
    );
}

#[test]
fn access_rights_setters_refuse_ill_formed_rules_and_keep_the_old_ones() {
    let unspecified_time_range = schedule(ObjectIdentifier::MAX_INSTANCE);
    let unspecified_location = BACnetDeviceObjectReference {
        device_identifier: Some(oid(ObjectType::DEVICE, ObjectIdentifier::MAX_INSTANCE)),
        object_identifier: oid(ObjectType::ACCESS_POINT, ObjectIdentifier::MAX_INSTANCE),
    };
    let with = |time_range_specifier, time_range, location_specifier, location| BACnetAccessRule {
        time_range_specifier,
        time_range,
        location_specifier,
        location,
        enable: true,
    };
    use AccessRuleLocationSpecifier as L;
    use AccessRuleTimeRangeSpecifier as T;
    let point = || Some(local(ObjectType::ACCESS_POINT, 2));

    let refused = [
        // SPECIFIED without its reference.
        with(T::SPECIFIED, None, L::SPECIFIED, point()),
        with(T::ALWAYS, None, L::SPECIFIED, None),
        // ALWAYS or ALL with a reference to something.
        with(T::ALWAYS, Some(schedule(1)), L::ALL, None),
        with(T::ALWAYS, None, L::ALL, point()),
        // Unspecified needs the device instance unused too.
        with(
            T::ALWAYS,
            Some(BACnetDeviceObjectPropertyReference::new_remote(
                oid(ObjectType::SCHEDULE, ObjectIdentifier::MAX_INSTANCE),
                85,
                oid(ObjectType::DEVICE, 99),
            )),
            L::ALL,
            None,
        ),
        // Specifiers past the two named values.
        with(T::from_raw(2), None, L::ALL, None),
        with(T::ALWAYS, None, L::from_raw(2), None),
        // A location that is neither an Access Point nor an Access Zone.
        rule(None, Some(local(ObjectType::ACCESS_DOOR, 2))),
        rule(None, Some(local(ObjectType::ANALOG_VALUE, 2))),
    ];
    let accepted = [
        rule(Some(schedule(1)), point()),
        // Unspecified references fit either specifier.
        with(
            T::ALWAYS,
            Some(unspecified_time_range.clone()),
            L::ALL,
            None,
        ),
        with(T::SPECIFIED, Some(unspecified_time_range), L::ALL, None),
        with(T::ALWAYS, None, L::ALL, Some(unspecified_location.clone())),
        with(T::ALWAYS, None, L::SPECIFIED, Some(unspecified_location)),
        with(
            T::ALWAYS,
            None,
            L::SPECIFIED,
            Some(local(
                ObjectType::ANALOG_VALUE,
                ObjectIdentifier::MAX_INSTANCE,
            )),
        ),
        // A time range may name any object's property, and the location may
        // sit in another device.
        rule(
            Some(BACnetDeviceObjectPropertyReference::new_local(
                oid(ObjectType::BINARY_VALUE, 4),
                85,
            )),
            Some(BACnetDeviceObjectReference {
                device_identifier: Some(oid(ObjectType::DEVICE, 99)),
                object_identifier: oid(ObjectType::ACCESS_ZONE, 3),
            }),
        ),
    ];

    let mut rights = AccessRightsObject::new(7, "AR-7").unwrap();
    rights.set_positive_access_rules(accepted.clone()).unwrap();
    rights.set_negative_access_rules(accepted.clone()).unwrap();
    for bad in refused {
        let list = [accepted[0].clone(), bad.clone()];
        assert_property_error(
            rights.set_positive_access_rules(list.clone()),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_property_error(
            rights.set_negative_access_rules(list),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_eq!(rights.positive_access_rules(), accepted, "{bad:?}");
        assert_eq!(rights.negative_access_rules(), accepted, "{bad:?}");
    }
    // An empty list clears the array.
    rights.set_negative_access_rules([]).unwrap();
    assert_eq!(
        rights
            .read_property(P::NEGATIVE_ACCESS_RULES, Some(0))
            .unwrap(),
        PropertyValue::Unsigned(0)
    );
}

#[test]
fn access_rights_rules_refuse_a_non_device_device_identifier() {
    // Either reference's device member must be a Device (#1285).
    let not_a_device = oid(ObjectType::ANALOG_VALUE, 99);
    let time_range = BACnetDeviceObjectPropertyReference::new_remote(
        oid(ObjectType::SCHEDULE, 1),
        85,
        not_a_device,
    );
    let location = BACnetDeviceObjectReference {
        device_identifier: Some(not_a_device),
        object_identifier: oid(ObjectType::ACCESS_POINT, 2),
    };
    let mut rights = AccessRightsObject::new(7, "AR-7").unwrap();
    for bad in [rule(Some(time_range), None), rule(None, Some(location))] {
        assert_property_error(
            rights.set_positive_access_rules([bad.clone()]),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_property_error(
            rights.set_negative_access_rules([bad]),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
    }
    assert!(rights.positive_access_rules().is_empty());
    assert!(rights.negative_access_rules().is_empty());
}

#[test]
fn access_rights_rule_arrays_stay_read_only_on_the_network() {
    let mut rights = AccessRightsObject::new(7, "AR-7").unwrap();
    let kept = rule(Some(schedule(1)), None);
    rights.set_positive_access_rules([kept.clone()]).unwrap();
    for property in [P::POSITIVE_ACCESS_RULES, P::NEGATIVE_ACCESS_RULES] {
        for (index, value) in [
            (
                None,
                PropertyValue::List(vec![element(&kept), element(&kept)]),
            ),
            (Some(1), element(&kept)),
            (Some(0), PropertyValue::Unsigned(3)),
        ] {
            assert_property_error(
                rights.write_property(property, index, value, None),
                ErrorCode::WRITE_ACCESS_DENIED,
            );
        }
    }
    assert_eq!(rights.positive_access_rules(), [kept]);
    assert!(rights.negative_access_rules().is_empty());
}
