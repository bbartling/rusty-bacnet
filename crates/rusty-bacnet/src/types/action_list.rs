//! Python mapping boundary for a Command object's Action lists (#1179).
//!
//! Each command is an `ActionCommand` mapping. This layer checks shapes and
//! Python types only; `CommandObject::set_action` decides what BACnet allows,
//! such as a priority from 1 to 16.

use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool};

use super::mapping::{mapping, object_identifier, optional_item, ranged_integer, required_item};
use super::{PyPropertyIdentifier, PyPropertyValue};

const REQUIRED: &[&str] = &["object_identifier", "property_identifier", "property_value"];
const OPTIONAL: &[&str] = &[
    "property_array_index",
    "priority",
    "post_delay",
    "quit_on_failure",
    "device_identifier",
];

/// Read `action`, a list of lists of `ActionCommand` mappings, one inner list
/// per Action element.
pub(crate) fn action_lists_from_py(action: &Bound<'_, PyAny>) -> PyResult<Vec<BACnetActionList>> {
    sequence(action, "action")?
        .iter()
        .enumerate()
        .map(|(list, commands)| {
            let name = format!("action[{list}]");
            let commands = sequence(commands, &name)?
                .iter()
                .enumerate()
                .map(|(index, command)| action_command(command, &format!("{name}[{index}]")))
                .collect::<PyResult<_>>()?;
            Ok(BACnetActionList { commands })
        })
        .collect()
}

fn sequence<'py>(value: &Bound<'py, PyAny>, name: &str) -> PyResult<Vec<Bound<'py, PyAny>>> {
    value
        .extract()
        .map_err(|_| PyTypeError::new_err(format!("{name} must be a list")))
}

fn action_command(value: &Bound<'_, PyAny>, name: &str) -> PyResult<BACnetActionCommand> {
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
    let property_value = required_item(value, name, "property_value")?
        .extract::<PyPropertyValue>()
        .map_err(|_| {
            PyTypeError::new_err(format!(
                "{} must be a PropertyValue",
                field("property_value")
            ))
        })?
        .inner;
    let optional_integer = |key: &str, maximum: u64| {
        optional_item(value, key)?
            .map(|item| ranged_integer(&item, &field(key), 0, maximum))
            .transpose()
    };
    let quit_on_failure = match optional_item(value, "quit_on_failure")? {
        None => false,
        Some(item) if item.is_instance_of::<PyBool>() => item.extract()?,
        Some(_) => {
            return Err(PyTypeError::new_err(format!(
                "{} must be a bool",
                field("quit_on_failure")
            )))
        }
    };
    Ok(BACnetActionCommand {
        device_identifier: optional_item(value, "device_identifier")?
            .map(|item| object_identifier(&item, &field("device_identifier")))
            .transpose()?,
        object_identifier: object_identifier(
            &required_item(value, name, "object_identifier")?,
            &field("object_identifier"),
        )?,
        property_identifier,
        property_array_index: optional_integer("property_array_index", u32::MAX.into())?
            .map(|index| index as u32),
        property_value,
        priority: optional_integer("priority", u8::MAX.into())?.map(|priority| priority as u8),
        post_delay: optional_integer("post_delay", u32::MAX.into())?.map(|delay| delay as u32),
        quit_on_failure,
        // No write has been made yet.
        write_successful: false,
    })
}

#[cfg(test)]
#[path = "action_list_tests.rs"]
mod tests;
