use super::*;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::types::{PyDict, PyList};

use crate::types::PyObjectIdentifier;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn minimal(py: Python<'_>) -> Bound<'_, PyDict> {
    let command = PyDict::new(py);
    command
        .set_item(
            "object_identifier",
            PyObjectIdentifier::from_rust(oid(ObjectType::ANALOG_OUTPUT, 1)),
        )
        .unwrap();
    command
        .set_item(
            "property_identifier",
            PyPropertyIdentifier {
                inner: PropertyIdentifier::PRESENT_VALUE,
            },
        )
        .unwrap();
    command
        .set_item(
            "property_value",
            PyPropertyValue::from_rust(PropertyValue::Real(50.0)),
        )
        .unwrap();
    command
}

fn lists<'py>(py: Python<'py>, commands: &[Bound<'py, PyDict>]) -> Bound<'py, PyList> {
    PyList::new(py, [PyList::new(py, commands).unwrap()]).unwrap()
}

#[test]
fn action_command_mappings_fill_every_field_and_default_the_optional_ones() {
    Python::initialize();
    Python::attach(|py| {
        let full = minimal(py);
        full.set_item("property_array_index", 3).unwrap();
        full.set_item("priority", 8).unwrap();
        full.set_item("post_delay", 5).unwrap();
        full.set_item("quit_on_failure", true).unwrap();
        full.set_item("write_successful", true).unwrap();
        full.set_item(
            "device_identifier",
            PyObjectIdentifier::from_rust(oid(ObjectType::DEVICE, 9)),
        )
        .unwrap();
        let empty = PyList::empty(py);
        let action =
            PyList::new(py, [PyList::new(py, [minimal(py), full]).unwrap(), empty]).unwrap();
        let parsed = action_lists_from_py(action.as_any()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed[1].commands.is_empty());
        let plain = BACnetActionCommand {
            device_identifier: None,
            object_identifier: oid(ObjectType::ANALOG_OUTPUT, 1),
            property_identifier: PropertyIdentifier::PRESENT_VALUE,
            property_array_index: None,
            property_value: PropertyValue::Real(50.0),
            priority: None,
            post_delay: None,
            quit_on_failure: false,
            write_successful: false,
        };
        assert_eq!(parsed[0].commands[0], plain);
        assert_eq!(
            parsed[0].commands[1],
            BACnetActionCommand {
                device_identifier: Some(oid(ObjectType::DEVICE, 9)),
                property_array_index: Some(3),
                priority: Some(8),
                post_delay: Some(5),
                quit_on_failure: true,
                // Taken so a read mapping can be given back, but only a run
                // sets it.
                write_successful: false,
                ..plain
            }
        );
        // None reads as absent.
        let nones = minimal(py);
        for key in OPTIONAL {
            nones.set_item(*key, py.None()).unwrap();
        }
        let parsed = action_lists_from_py(lists(py, &[nones]).as_any()).unwrap();
        assert_eq!(parsed[0].commands[0].priority, None);
        assert!(!parsed[0].commands[0].quit_on_failure);
        assert!(!parsed[0].commands[0].write_successful);
    });
}

#[test]
fn action_command_mappings_refuse_bad_shapes_and_types() {
    Python::initialize();
    Python::attach(|py| {
        let error = |action: &Bound<'_, PyAny>| action_lists_from_py(action).unwrap_err();
        let type_error = |action: &Bound<'_, PyAny>, needle: &str| {
            let error = error(action);
            assert!(error.is_instance_of::<PyTypeError>(py), "{error}");
            assert!(error.to_string().contains(needle), "{error}");
        };
        let value_error = |action: &Bound<'_, PyAny>, needle: &str| {
            let error = error(action);
            assert!(error.is_instance_of::<PyValueError>(py), "{error}");
            assert!(error.to_string().contains(needle), "{error}");
        };
        type_error(
            pyo3::types::PyString::new(py, "x").as_any(),
            "action must be a list",
        );
        type_error(
            PyList::new(py, [1]).unwrap().as_any(),
            "action[0] must be a list",
        );
        type_error(
            PyList::new(py, [PyList::new(py, [1]).unwrap()])
                .unwrap()
                .as_any(),
            "action[0][0] must be a mapping",
        );
        let missing = minimal(py);
        missing.del_item("property_value").unwrap();
        value_error(
            lists(py, &[missing]).as_any(),
            "missing required key 'property_value'",
        );
        let unknown = minimal(py);
        unknown.set_item("quit_on_faliure", true).unwrap();
        value_error(
            lists(py, &[unknown]).as_any(),
            "unknown key 'quit_on_faliure'",
        );
        let wide = minimal(py);
        wide.set_item("priority", 256).unwrap();
        value_error(lists(py, &[wide]).as_any(), "action[0][0].priority");
        // A device identifier names a Device or nothing (#1308), wherever the
        // command sits.
        let remote = minimal(py);
        remote
            .set_item(
                "device_identifier",
                PyObjectIdentifier::from_rust(oid(ObjectType::ANALOG_VALUE, 9)),
            )
            .unwrap();
        value_error(
            lists(py, &[minimal(py), remote]).as_any(),
            "action[0][1]: the device must be a Device object identifier",
        );
        for (key, bad) in [
            (
                "quit_on_failure",
                1_i64.into_pyobject(py).unwrap().into_any(),
            ),
            (
                "write_successful",
                1_i64.into_pyobject(py).unwrap().into_any(),
            ),
            (
                "priority",
                true.into_pyobject(py).unwrap().to_owned().into_any(),
            ),
            (
                "property_value",
                50.0_f64.into_pyobject(py).unwrap().into_any(),
            ),
            (
                "object_identifier",
                1_i64.into_pyobject(py).unwrap().into_any(),
            ),
        ] {
            let command = minimal(py);
            command.set_item(key, bad).unwrap();
            type_error(lists(py, &[command]).as_any(), key);
        }
    });
}
