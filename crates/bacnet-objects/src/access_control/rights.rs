use bacnet_encoding::constructed::encode_access_rule;
use bacnet_types::constructed::BACnetAccessRule;
use bacnet_types::enums::{AccessRuleLocationSpecifier, AccessRuleTimeRangeSpecifier};

use super::*;

// AccessRightsObject (type 34)
// ---------------------------------------------------------------------------

/// BACnet Access Rights object (type 34).
///
/// Holds the positive and negative access rules that credentials and users
/// are assigned. Both rule arrays are BACnetARRAYs of `BACnetAccessRule`
/// that the application provisions with
/// [`set_positive_access_rules`](Self::set_positive_access_rules) and
/// [`set_negative_access_rules`](Self::set_negative_access_rules); Table
/// 12-39 doesn't require them to be writable, so the network reads them only.
/// The object stores the rules without evaluating them.
pub struct AccessRightsObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    global_identifier: u64,
    positive_access_rules: Vec<BACnetAccessRule>,
    negative_access_rules: Vec<BACnetAccessRule>,
    status_flags: StatusFlags,
    reliability: Reliability,
}

impl AccessRightsObject {
    /// Create a new Access Rights object with no access rules.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_RIGHTS, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            global_identifier: 0,
            positive_access_rules: Vec::new(),
            negative_access_rules: Vec::new(),
            status_flags: StatusFlags::empty(),
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }

    /// Replace Positive_Access_Rules, the rules that grant access.
    ///
    /// The whole list is refused with VALUE_OUT_OF_RANGE, keeping the rules
    /// set before, when any rule (Clause 12.34.9.1):
    ///
    /// - names a device that isn't a Device in either reference (#1285);
    /// - holds a specifier outside its two named values;
    /// - is SPECIFIED for a member whose reference is left out;
    /// - is ALWAYS or ALL for a member whose reference is present and not
    ///   unspecified;
    /// - is SPECIFIED for a location that names neither an Access Point nor
    ///   an Access Zone and isn't unspecified.
    ///
    /// A reference is unspecified when its object identifier, and its device
    /// identifier if it has one, carry instance 4194303. A SPECIFIED member
    /// may hold one, standing for nothing to match yet. The time range may
    /// name a property of any object; a Schedule's Present_Value is typical.
    pub fn set_positive_access_rules(
        &mut self,
        rules: impl IntoIterator<Item = BACnetAccessRule>,
    ) -> Result<(), Error> {
        self.positive_access_rules = checked_rules(rules)?;
        Ok(())
    }

    /// Replace Negative_Access_Rules, the rules that deny access, with the
    /// same checks as
    /// [`set_positive_access_rules`](Self::set_positive_access_rules).
    pub fn set_negative_access_rules(
        &mut self,
        rules: impl IntoIterator<Item = BACnetAccessRule>,
    ) -> Result<(), Error> {
        self.negative_access_rules = checked_rules(rules)?;
        Ok(())
    }

    /// The stored Positive_Access_Rules.
    pub fn positive_access_rules(&self) -> &[BACnetAccessRule] {
        &self.positive_access_rules
    }

    /// The stored Negative_Access_Rules.
    pub fn negative_access_rules(&self) -> &[BACnetAccessRule] {
        &self.negative_access_rules
    }
}

/// `rules` collected once every one has passed [`check_access_rule`].
fn checked_rules(
    rules: impl IntoIterator<Item = BACnetAccessRule>,
) -> Result<Vec<BACnetAccessRule>, Error> {
    let rules: Vec<BACnetAccessRule> = rules.into_iter().collect();
    rules.iter().try_for_each(check_access_rule)?;
    Ok(rules)
}

/// Refuse with VALUE_OUT_OF_RANGE a rule the setters' rules turn away (see
/// [`AccessRightsObject::set_positive_access_rules`]). The device members go
/// through the shared `check_device_member` first.
fn check_access_rule(rule: &BACnetAccessRule) -> Result<(), Error> {
    let time_range_device = rule.time_range.as_ref().and_then(|r| r.device_identifier);
    crate::device_reference::check_device_member(time_range_device)?;
    let location_device = rule.location.as_ref().and_then(|r| r.device_identifier);
    crate::device_reference::check_device_member(location_device)?;

    let time_range_ok = match rule.time_range_specifier {
        AccessRuleTimeRangeSpecifier::SPECIFIED => rule.time_range.is_some(),
        AccessRuleTimeRangeSpecifier::ALWAYS => rule
            .time_range
            .as_ref()
            .is_none_or(|r| unspecified(r.object_identifier, r.device_identifier)),
        _ => false,
    };
    let location_ok = match rule.location_specifier {
        AccessRuleLocationSpecifier::SPECIFIED => rule.location.as_ref().is_some_and(|r| {
            matches!(
                r.object_identifier.object_type(),
                ObjectType::ACCESS_POINT | ObjectType::ACCESS_ZONE
            ) || unspecified(r.object_identifier, r.device_identifier)
        }),
        AccessRuleLocationSpecifier::ALL => rule
            .location
            .as_ref()
            .is_none_or(|r| unspecified(r.object_identifier, r.device_identifier)),
        _ => false,
    };
    if time_range_ok && location_ok {
        Ok(())
    } else {
        Err(common::value_out_of_range_error())
    }
}

/// Whether a rule's reference is unspecified: its object, and its device if
/// it names one, both carry the reserved instance number 4194303.
fn unspecified(object: ObjectIdentifier, device: Option<ObjectIdentifier>) -> bool {
    let unused = |oid: ObjectIdentifier| oid.instance_number() == ObjectIdentifier::MAX_INSTANCE;
    unused(object) && device.is_none_or(unused)
}

/// A rule array as `common::read_array` serves it: each rule in its Clause
/// 21 form.
fn rule_values(rules: &[BACnetAccessRule]) -> Vec<PropertyValue> {
    rules
        .iter()
        .map(|rule| {
            let mut buf = BytesMut::new();
            encode_access_rule(&mut buf, rule);
            PropertyValue::ApplicationData(buf.to_vec())
        })
        .collect()
}

impl BACnetObject for AccessRightsObject {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }

    fn object_name(&self) -> &str {
        &self.name
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        // Table 12-39 has no Out_Of_Service (#1064), and Clause 12.34 holds the
        // OUT_OF_SERVICE flag FALSE.
        if let Some(result) =
            read_common_properties!(self, property, array_index, no_out_of_service)
        {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => Ok(PropertyValue::Enumerated(
                ObjectType::ACCESS_RIGHTS.to_raw(),
            )),
            p if p == PropertyIdentifier::GLOBAL_IDENTIFIER => {
                Ok(PropertyValue::Unsigned(self.global_identifier))
            }
            p if p == PropertyIdentifier::POSITIVE_ACCESS_RULES => {
                common::read_array(rule_values(&self.positive_access_rules), array_index)
            }
            p if p == PropertyIdentifier::NEGATIVE_ACCESS_RULES => {
                common::read_array(rule_values(&self.negative_access_rules), array_index)
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::GLOBAL_IDENTIFIER => {
                if let PropertyValue::Unsigned(v) = value {
                    self.global_identifier = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            // The rule arrays are R rows (Table 12-39): refused here as
            // read-only, like the other unhandled rows.
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        super::metadata_identity::for_access_rights_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }
}

#[cfg(test)]
#[path = "rights_tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
