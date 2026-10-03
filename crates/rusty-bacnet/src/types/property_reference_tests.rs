use super::*;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::primitives::ObjectIdentifier;
use pyo3::exceptions::PyValueError;
use pyo3::types::{PyDict, PyList};

use crate::types::PyObjectIdentifier;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn minimal(py: Python<'_>) -> Bound<'_, PyDict> {
    let reference = PyDict::new(py);
    reference
        .set_item(
            "object_identifier",
            PyObjectIdentifier::from_rust(oid(ObjectType::ANALOG_VALUE, 1)),
        )
        .unwrap();
    reference
        .set_item(
            "property_identifier",
            PyPropertyIdentifier {
                inner: PropertyIdentifier::PRESENT_VALUE,
            },
        )
        .unwrap();
    reference
}

#[test]
fn reference_mappings_fill_every_field_and_default_the_optional_ones() {
    Python::initialize();
    Python::attach(|py| {
        let full = minimal(py);
        full.set_item("property_array_index", 3).unwrap();
        full.set_item(
            "device_identifier",
            PyObjectIdentifier::from_rust(oid(ObjectType::DEVICE, 9)),
        )
        .unwrap();
        let nones = minimal(py);
        for key in OPTIONAL {
            nones.set_item(*key, py.None()).unwrap();
        }
        let list = PyList::new(py, [minimal(py), full, nones]).unwrap();
        let plain = BACnetDeviceObjectPropertyReference::new_local(
            oid(ObjectType::ANALOG_VALUE, 1),
            PropertyIdentifier::PRESENT_VALUE.to_raw(),
        );
        assert_eq!(
            property_references_from_py(list.as_any(), "members").unwrap(),
            [
                plain.clone(),
                BACnetDeviceObjectPropertyReference {
                    property_array_index: Some(3),
                    device_identifier: Some(oid(ObjectType::DEVICE, 9)),
                    ..plain.clone()
                },
                plain,
            ]
        );
    });
}

fn listed<'py>(py: Python<'py>, reference: Bound<'py, PyDict>) -> Bound<'py, PyList> {
    PyList::new(py, [reference]).unwrap()
}

#[test]
fn reference_mappings_refuse_bad_shapes_and_types() {
    Python::initialize();
    Python::attach(|py| {
        let error =
            |value: &Bound<'_, PyAny>| property_references_from_py(value, "members").unwrap_err();
        let type_error = |value: &Bound<'_, PyAny>, needle: &str| {
            let error = error(value);
            assert!(error.is_instance_of::<PyTypeError>(py), "{error}");
            assert!(error.to_string().contains(needle), "{error}");
        };
        let value_error = |value: &Bound<'_, PyAny>, needle: &str| {
            let error = error(value);
            assert!(error.is_instance_of::<PyValueError>(py), "{error}");
            assert!(error.to_string().contains(needle), "{error}");
        };
        type_error(
            pyo3::types::PyString::new(py, "x").as_any(),
            "members must be a list",
        );
        type_error(
            PyList::new(py, [1]).unwrap().as_any(),
            "members[0] must be a mapping",
        );
        let missing = minimal(py);
        missing.del_item("property_identifier").unwrap();
        value_error(
            listed(py, missing).as_any(),
            "missing required key 'property_identifier'",
        );
        let unknown = minimal(py);
        unknown.set_item("array_index", 1).unwrap();
        value_error(listed(py, unknown).as_any(), "unknown key 'array_index'");
        let wide = minimal(py);
        wide.set_item("property_array_index", 1_u64 << 32).unwrap();
        value_error(listed(py, wide).as_any(), "members[0].property_array_index");
        let not_a_device = minimal(py);
        not_a_device
            .set_item(
                "device_identifier",
                PyObjectIdentifier::from_rust(oid(ObjectType::ANALOG_INPUT, 9)),
            )
            .unwrap();
        value_error(
            listed(py, not_a_device).as_any(),
            "members[0]: the device must be a Device object identifier",
        );
        for (key, bad) in [
            (
                "property_identifier",
                85_i64.into_pyobject(py).unwrap().into_any(),
            ),
            (
                "object_identifier",
                1_i64.into_pyobject(py).unwrap().into_any(),
            ),
            (
                "device_identifier",
                9_i64.into_pyobject(py).unwrap().into_any(),
            ),
            (
                "property_array_index",
                true.into_pyobject(py).unwrap().to_owned().into_any(),
            ),
        ] {
            let reference = minimal(py);
            reference.set_item(key, bad).unwrap();
            type_error(listed(py, reference).as_any(), key);
        }
    });
}
