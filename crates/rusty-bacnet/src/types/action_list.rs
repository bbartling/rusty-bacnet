//! Python mapping boundary for a Command object's Action lists (#1179).
//!
//! Each command is an `ActionCommand` mapping. This layer checks shapes,
//! Python types and the device identifier (a non-Device raises ValueError,
//! as for any other device reference, #1308); `CommandObject::set_action`
//! decides what else BACnet allows, such as a priority from 1 to 16.

use bacnet_types::constructed::{BACnetActionCommand, BACnetActionList};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool};

use super::mapping::{fixed_integer, mapping, object_identifier, optional_item, required_item};
use super::{PyPropertyIdentifier, PyPropertyValue};

const REQUIRED: &[&str] = &["object_identifier", "property_identifier", "property_value"];
const OPTIONAL: &[&str] = &[
    "property_array_index",
    "priority",
    "post_delay",
    "quit_on_failure",
    "device_identifier",
    "write_successful",
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
    let optional_u8 = |key: &str| {
        optional_item(value, key)?
            .map(|item| fixed_integer::<u8>(&item, &field(key)))
            .transpose()
    };
    let optional_u32 = |key: &str| {
        optional_item(value, key)?
            .map(|item| fixed_integer::<u32>(&item, &field(key)))
            .transpose()
    };
    let flag = |key: &str| match optional_item(value, key)? {
        None => Ok(false),
        Some(item) if item.is_instance_of::<PyBool>() => item.extract(),
        Some(_) => Err(PyTypeError::new_err(format!(
            "{} must be a bool",
            field(key)
        ))),
    };
    let device_identifier = optional_item(value, "device_identifier")?
        .map(|item| object_identifier(&item, &field("device_identifier")))
        .transpose()?;
    super::check_device(device_identifier, name)?;
    Ok(BACnetActionCommand {
        device_identifier,
        object_identifier: object_identifier(
            &required_item(value, name, "object_identifier")?,
            &field("object_identifier"),
        )?,
        property_identifier,
        property_array_index: optional_u32("property_array_index")?,
        property_value,
        priority: optional_u8("priority")?,
        post_delay: optional_u32("post_delay")?,
        quit_on_failure: flag("quit_on_failure")?,
        // A read of Action carries this flag, so the key is taken (and
        // type-checked) for a read mapping to be given back, but its value is
        // ignored: only a run sets it, so a command not yet run reads FALSE.
        write_successful: flag("write_successful").map(|_| false)?,
    })
}

#[cfg(test)]
#[path = "action_list_tests.rs"]
mod tests;
