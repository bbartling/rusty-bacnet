//! Python boundary for `BACnetDeviceObjectPropertyReference`: the mapping an
//! Access Rights rule's `time_range` takes (#1316) and the member list of
//! `add_channel` (#1262).
//!
//! A reference is either a tuple naming a property in this device,
//! `(object, property)` or `(object, property, array_index)`, or a mapping
//! keyed like an `ActionCommand`'s reference fields, which can also carry a
//! `device_identifier`. This layer checks shapes, Python types and the device
//! member (a non-Device raises ValueError, as for `door_members`, #1285); the
//! object's own setter decides the rest.

use bacnet_types::constructed::{device_identifier_is_device, BACnetDeviceObjectPropertyReference};
use bacnet_types::primitives::ObjectIdentifier;
use pyo3::exceptions::{PyOverflowError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyMapping, PyTuple};

use super::mapping::{
    mapping, object_identifier, optional_item, ranged_integer, required_item, validate_keys,
};
use super::PyPropertyIdentifier;

const REQUIRED: &[&str] = &["object_identifier", "property_identifier"];
const OPTIONAL: &[&str] = &["property_array_index", "device_identifier"];

/// Read `references`, a list whose elements are each a reference tuple or a
/// reference mapping; `name` is the keyword the errors name.
pub(crate) fn property_references_from_py(
    references: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<Vec<BACnetDeviceObjectPropertyReference>> {
    let references: Vec<Bound<'_, PyAny>> = references
        .extract()
        .map_err(|_| PyTypeError::new_err(format!("{name} must be a list")))?;
    references
        .iter()
        .enumerate()
        .map(|(index, reference)| tuple_or_mapping(reference, &format!("{name}[{index}]")))
        .collect()
}

fn tuple_or_mapping(
    value: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<BACnetDeviceObjectPropertyReference> {
    if let Ok(tuple) = value.cast::<PyTuple>() {
        return local_tuple(tuple, name);
    }
    if value.cast::<PyMapping>().is_ok() {
        return device_object_property_reference(value, name);
    }
    Err(PyTypeError::new_err(format!(
        "{name} must be an (object, property) or (object, property, array_index) tuple, \
         or a mapping"
    )))
}

/// A property of an object in this device. An array index outside
/// unsigned32 raises OverflowError, as `add_group`'s indexes do.
fn local_tuple(
    tuple: &Bound<'_, PyTuple>,
    name: &str,
) -> PyResult<BACnetDeviceObjectPropertyReference> {
    if !(2..=3).contains(&tuple.len()) {
        return Err(PyTypeError::new_err(format!(
            "{name} must have 2 or 3 items, got {}",
            tuple.len()
        )));
    }
    let object = object_identifier(&tuple.get_item(0)?, &format!("{name} object"))?;
    let property = property_identifier(&tuple.get_item(1)?, &format!("{name} property"))?;
    let reference = BACnetDeviceObjectPropertyReference::new_local(object, property);
    if tuple.len() == 2 {
        return Ok(reference);
    }
    let index = tuple.get_item(2)?;
    if index.is_none() {
        return Ok(reference);
    }
    let index = index.extract::<u32>().map_err(|error| {
        if error.is_instance_of::<PyOverflowError>(tuple.py()) {
            error
        } else {
            PyTypeError::new_err(format!("{name} array index must be an int or None"))
        }
    })?;
    Ok(reference.with_index(index))
}

/// A `BACnetDeviceObjectPropertyReference` mapping: `object_identifier` and
/// `property_identifier`, with the optional `property_array_index` and
/// `device_identifier`.
pub(crate) fn device_object_property_reference(
    value: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<BACnetDeviceObjectPropertyReference> {
    let value = mapping(value, name)?;
    validate_keys(value, name, REQUIRED, OPTIONAL)?;
    let property_identifier = property_identifier(
        &required_item(value, name, "property_identifier")?,
        &format!("{name}.property_identifier"),
    )?;
    let device_identifier = optional_item(value, "device_identifier")?
        .map(|item| object_identifier(&item, &format!("{name}.device_identifier")))
        .transpose()?;
    check_device(device_identifier, name)?;
    Ok(BACnetDeviceObjectPropertyReference {
        object_identifier: object_identifier(
            &required_item(value, name, "object_identifier")?,
            &format!("{name}.object_identifier"),
        )?,
        property_identifier,
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

/// The raw identifier of a `PropertyIdentifier`; anything else is a
/// TypeError.
fn property_identifier(value: &Bound<'_, PyAny>, name: &str) -> PyResult<u32> {
    value
        .extract::<PyPropertyIdentifier>()
        .map(|property| property.to_rust().to_raw())
        .map_err(|_| PyTypeError::new_err(format!("{name} must be a PropertyIdentifier")))
}

/// ValueError for a device member that isn't a Device object identifier.
pub(crate) fn check_device(device: Option<ObjectIdentifier>, name: &str) -> PyResult<()> {
    if device_identifier_is_device(device) {
        Ok(())
    } else {
        Err(PyValueError::new_err(format!(
            "{name}: the device must be a Device object identifier"
        )))
    }
}

#[cfg(test)]
#[path = "property_reference_tests.rs"]
mod tests;
