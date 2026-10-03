use super::*;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use pyo3::exceptions::PyOverflowError;
use pyo3::types::{PyDict, PyList};

use crate::types::PyObjectIdentifier;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn py_oid(py: Python<'_>, object_type: ObjectType, instance: u32) -> Bound<'_, PyAny> {
    Bound::new(
        py,
        PyObjectIdentifier::from_rust(oid(object_type, instance)),
    )
    .unwrap()
    .into_any()
}

fn present_value(py: Python<'_>) -> Bound<'_, PyAny> {
    Bound::new(
        py,
        PyPropertyIdentifier {
            inner: PropertyIdentifier::PRESENT_VALUE,
        },
    )
    .unwrap()
    .into_any()
}

fn tuple<'py>(py: Python<'py>, items: Vec<Bound<'py, PyAny>>) -> Bound<'py, PyAny> {
    PyTuple::new(py, items).unwrap().into_any()
}

fn int(py: Python<'_>, value: i64) -> Bound<'_, PyAny> {
    value.into_pyobject(py).unwrap().into_any()
}

/// AV-1's Present_Value as a reference mapping.
fn av1_mapping(py: Python<'_>) -> Bound<'_, PyDict> {
    let reference = PyDict::new(py);
    reference
        .set_item("object_identifier", py_oid(py, ObjectType::ANALOG_VALUE, 1))
        .unwrap();
    reference
        .set_item("property_identifier", present_value(py))
        .unwrap();
    reference
}

fn parse<'py>(
    py: Python<'py>,
    references: &[Bound<'py, PyAny>],
) -> PyResult<Vec<BACnetDeviceObjectPropertyReference>> {
    property_references_from_py(PyList::new(py, references).unwrap().as_any(), "members")
}

#[test]
fn property_reference_tuples_and_mappings_convert() {
    Python::initialize();
    Python::attach(|py| {
        let ao1 = || py_oid(py, ObjectType::ANALOG_OUTPUT, 1);
        let remote = av1_mapping(py);
        remote.set_item("property_array_index", 4).unwrap();
        remote
            .set_item("device_identifier", py_oid(py, ObjectType::DEVICE, 99))
            .unwrap();
        let nones = av1_mapping(py);
        nones.set_item("property_array_index", py.None()).unwrap();
        nones.set_item("device_identifier", py.None()).unwrap();

        let parsed = parse(
            py,
            &[
                tuple(py, vec![ao1(), present_value(py)]),
                tuple(py, vec![ao1(), present_value(py), int(py, 8)]),
                tuple(py, vec![ao1(), present_value(py), py.None().into_bound(py)]),
                av1_mapping(py).into_any(),
                remote.into_any(),
                nones.into_any(),
            ],
        )
        .unwrap();
        let pv = PropertyIdentifier::PRESENT_VALUE.to_raw();
        let ao1 =
            BACnetDeviceObjectPropertyReference::new_local(oid(ObjectType::ANALOG_OUTPUT, 1), pv);
        let av1 =
            BACnetDeviceObjectPropertyReference::new_local(oid(ObjectType::ANALOG_VALUE, 1), pv);
        assert_eq!(
            parsed,
            vec![
                ao1.clone(),
                ao1.clone().with_index(8),
                ao1,
                av1.clone(),
                BACnetDeviceObjectPropertyReference::new_remote(
                    oid(ObjectType::ANALOG_VALUE, 1),
                    pv,
                    oid(ObjectType::DEVICE, 99),
                )
                .with_index(4),
                av1,
            ]
        );
        assert_eq!(parse(py, &[]).unwrap(), vec![]);
    });
}

#[test]
fn property_reference_errors_follow_the_neighbouring_conversions() {
    Python::initialize();
    Python::attach(|py| {
        let ao1 = || py_oid(py, ObjectType::ANALOG_OUTPUT, 1);
        let pv = || present_value(py);

        // Not a list at all.
        let error = property_references_from_py(&int(py, 3), "members").unwrap_err();
        assert!(error.is_instance_of::<PyTypeError>(py), "{error}");

        let type_errors: Vec<Bound<'_, PyAny>> = vec![
            // A bare object, without its property.
            ao1(),
            // Too few and too many items.
            tuple(py, vec![ao1()]),
            tuple(py, vec![ao1(), pv(), int(py, 1), int(py, 2)]),
            // The items out of order, and a property given as a number.
            tuple(py, vec![pv(), ao1()]),
            tuple(py, vec![ao1(), int(py, 85)]),
            // An index that isn't an int.
            tuple(
                py,
                vec![ao1(), pv(), "1".into_pyobject(py).unwrap().into_any()],
            ),
            // A list where the tuple goes.
            PyList::new(py, [ao1(), pv()]).unwrap().into_any(),
            // A mapping whose property is a number.
            {
                let reference = av1_mapping(py);
                reference.set_item("property_identifier", 85).unwrap();
                reference.into_any()
            },
        ];
        for reference in type_errors {
            let error = parse(py, std::slice::from_ref(&reference)).unwrap_err();
            assert!(
                error.is_instance_of::<PyTypeError>(py),
                "{reference}: {error}"
            );
        }

        // A tuple index outside unsigned32 overflows, as `add_group`'s do.
        for index in [-1, 1 << 32] {
            let reference = tuple(py, vec![ao1(), pv(), int(py, index)]);
            let error = parse(py, &[reference]).unwrap_err();
            assert!(error.is_instance_of::<PyOverflowError>(py), "{error}");
        }

        let value_errors: Vec<Bound<'_, PyAny>> = vec![
            // An unknown key.
            {
                let reference = av1_mapping(py);
                reference.set_item("priority", 8).unwrap();
                reference.into_any()
            },
            // A missing key.
            {
                let reference = av1_mapping(py);
                reference.del_item("object_identifier").unwrap();
                reference.into_any()
            },
            // A device member that isn't a Device.
            {
                let reference = av1_mapping(py);
                reference.set_item("device_identifier", ao1()).unwrap();
                reference.into_any()
            },
            // A mapping's index outside unsigned32, as a `time_range`'s is.
            {
                let reference = av1_mapping(py);
                reference.set_item("property_array_index", -1).unwrap();
                reference.into_any()
            },
        ];
        for reference in value_errors {
            let error = parse(py, std::slice::from_ref(&reference)).unwrap_err();
            assert!(
                error.is_instance_of::<PyValueError>(py),
                "{reference}: {error}"
            );
        }

        // The error names the element at fault.
        let good = tuple(py, vec![ao1(), pv()]);
        let error = parse(py, &[good, tuple(py, vec![ao1(), int(py, 85)])]).unwrap_err();
        assert!(error.to_string().contains("members[1] property"), "{error}");
    });
}
