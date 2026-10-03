//! Python mapping boundary for an Access Rights object's rule arrays
//! (#1316).
//!
//! Each rule is an `AccessRule` mapping. A missing or `None` time range or
//! location stands for ALWAYS or ALL, and a given one for SPECIFIED. This
//! layer checks shapes, Python types and the device member of each reference
//! (a non-Device raises ValueError, as for `door_members`, #1285);
//! `AccessRightsObject`'s setters decide the rest, such as a location that is
//! neither an Access Point nor an Access Zone.

use bacnet_types::constructed::{
    device_identifier_is_device, BACnetAccessRule, BACnetDeviceObjectPropertyReference,
    BACnetDeviceObjectReference,
};
use bacnet_types::primitives::ObjectIdentifier;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool};

use super::mapping::{
    mapping, object_identifier, optional_item, ranged_integer, required_item, validate_keys,
};
use super::{PyObjectIdentifier, PyPropertyIdentifier};

const RULE_REQUIRED: &[&str] = &["enable"];
const RULE_OPTIONAL: &[&str] = &["time_range", "location"];
const TIME_RANGE_REQUIRED: &[&str] = &["object_identifier", "property_identifier"];
const TIME_RANGE_OPTIONAL: &[&str] = &["property_array_index", "device_identifier"];

/// Read `rules`, a list of `AccessRule` mappings; `name` is the keyword the
/// errors name.
pub(crate) fn access_rules_from_py(
    rules: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<Vec<BACnetAccessRule>> {
    let rules: Vec<Bound<'_, PyAny>> = rules
        .extract()
        .map_err(|_| PyTypeError::new_err(format!("{name} must be a list")))?;
    rules
        .iter()
        .enumerate()
        .map(|(index, rule)| access_rule(rule, &format!("{name}[{index}]")))
        .collect()
}

fn access_rule(value: &Bound<'_, PyAny>, name: &str) -> PyResult<BACnetAccessRule> {
    let value = mapping(value, name)?;
    validate_keys(value, name, RULE_REQUIRED, RULE_OPTIONAL)?;
    let enable = required_item(value, name, "enable")?;
    if !enable.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err(format!(
            "{name}.enable must be a bool"
        )));
    }
    let time_range = optional_item(value, "time_range")?
        .map(|item| time_range(&item, &format!("{name}.time_range")))
        .transpose()?;
    let location = optional_item(value, "location")?
        .map(|item| location(&item, &format!("{name}.location")))
        .transpose()?;
    Ok(BACnetAccessRule::new(
        time_range,
        location,
        enable.extract()?,
    ))
}

/// A `BACnetDeviceObjectPropertyReference` mapping, keyed like an
/// `ActionCommand`'s reference fields.
fn time_range(
    value: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<BACnetDeviceObjectPropertyReference> {
    let value = mapping(value, name)?;
    validate_keys(value, name, TIME_RANGE_REQUIRED, TIME_RANGE_OPTIONAL)?;
    let property_identifier = required_item(value, name, "property_identifier")?
        .extract::<PyPropertyIdentifier>()
        .map_err(|_| {
            PyTypeError::new_err(format!(
                "{name}.property_identifier must be a PropertyIdentifier"
            ))
        })?
        .to_rust();
    let device_identifier = optional_item(value, "device_identifier")?
        .map(|item| object_identifier(&item, &format!("{name}.device_identifier")))
        .transpose()?;
    check_device(device_identifier, name)?;
    Ok(BACnetDeviceObjectPropertyReference {
        object_identifier: object_identifier(
            &required_item(value, name, "object_identifier")?,
            &format!("{name}.object_identifier"),
        )?,
        property_identifier: property_identifier.to_raw(),
        property_array_index: optional_item(value, "property_array_index")?
            .map(|item| {
                ranged_integer(
                    &item,
                    &format!("{name}.property_array_index"),
                    0,
                    u32::MAX.into(),
                )
            })
            .transpose()?
            .map(|index| index as u32),
        device_identifier,
    })
}

/// An `ObjectIdentifier` in this device or a `(device, object)` pair, the
/// forms `door_members` takes.
fn location(value: &Bound<'_, PyAny>, name: &str) -> PyResult<BACnetDeviceObjectReference> {
    if let Ok(object) = value.extract::<PyObjectIdentifier>() {
        return Ok(object.to_rust().into());
    }
    let (device, object) = value
        .extract::<(PyObjectIdentifier, PyObjectIdentifier)>()
        .map_err(|_| {
            PyTypeError::new_err(format!(
                "{name} must be an ObjectIdentifier or a (device, object) pair"
            ))
        })?;
    let device_identifier = Some(device.to_rust());
    check_device(device_identifier, name)?;
    Ok(BACnetDeviceObjectReference {
        device_identifier,
        object_identifier: object.to_rust(),
    })
}

/// ValueError for a device member that isn't a Device object identifier.
fn check_device(device: Option<ObjectIdentifier>, name: &str) -> PyResult<()> {
    if device_identifier_is_device(device) {
        Ok(())
    } else {
        Err(PyValueError::new_err(format!(
            "{name}: the device must be a Device object identifier"
        )))
    }
}

#[cfg(test)]
#[path = "access_rule_tests.rs"]
mod tests;
