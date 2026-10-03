//! Python mapping boundary for BACnetDeviceObjectPropertyReference values,
//! such as a Trend Log Multiple's members (#1235).
//!
//! Each reference is a `DeviceObjectPropertyReference` mapping. This layer
//! checks shapes and Python types only; the object taking the references
//! decides what BACnet allows, such as how many it holds.

use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

use super::mapping::{mapping, object_identifier, optional_item, ranged_integer, required_item};
use super::PyPropertyIdentifier;

const REQUIRED: &[&str] = &["object_identifier", "property_identifier"];
const OPTIONAL: &[&str] = &["property_array_index", "device_identifier"];

/// Read `value`, a list of `DeviceObjectPropertyReference` mappings, in
/// order. `name` labels the errors.
pub(crate) fn property_references_from_py(
    value: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<Vec<BACnetDeviceObjectPropertyReference>> {
    let items: Vec<Bound<'_, PyAny>> = value
        .extract()
        .map_err(|_| PyTypeError::new_err(format!("{name} must be a list")))?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| reference(item, &format!("{name}[{index}]")))
        .collect()
}

fn reference(
    value: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<BACnetDeviceObjectPropertyReference> {
    let value = mapping(value, name)?;
    super::mapping::validate_keys(value, name, REQUIRED, OPTIONAL)?;
    let field = |key: &str| format!("{name}.{key}");
    let property_identifier = required_item(value, name, "property_identifier")?
        .extract::<PyPropertyIdentifier>()
        .map_err(|_| {
            PyTypeError::new_err(format!(
                "{} must be a PropertyIdentifier",
                field("property_identifier")
            ))
        })?
        .to_rust();
    Ok(BACnetDeviceObjectPropertyReference {
        object_identifier: object_identifier(
            &required_item(value, name, "object_identifier")?,
            &field("object_identifier"),
        )?,
        property_identifier: property_identifier.to_raw(),
        property_array_index: optional_item(value, "property_array_index")?
            .map(|item| ranged_integer(&item, &field("property_array_index"), 0, u32::MAX.into()))
            .transpose()?
            .map(|index| index as u32),
        device_identifier: optional_item(value, "device_identifier")?
            .map(|item| object_identifier(&item, &field("device_identifier")))
            .transpose()?,
    })
}

#[cfg(test)]
#[path = "property_reference_tests.rs"]
mod tests;
