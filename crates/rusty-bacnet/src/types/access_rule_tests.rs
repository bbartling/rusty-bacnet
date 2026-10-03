use super::*;
use bacnet_types::enums::{
    AccessRuleLocationSpecifier, AccessRuleTimeRangeSpecifier, ObjectType, PropertyIdentifier,
};
use pyo3::types::{PyDict, PyList, PyTuple};

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

/// Schedule 1's Present_Value as a `time_range` mapping.
fn schedule_time_range(py: Python<'_>) -> Bound<'_, PyDict> {
    let time_range = PyDict::new(py);
    time_range
        .set_item("object_identifier", py_oid(py, ObjectType::SCHEDULE, 1))
        .unwrap();
    time_range
        .set_item(
            "property_identifier",
            PyPropertyIdentifier {
                inner: PropertyIdentifier::PRESENT_VALUE,
            },
        )
        .unwrap();
    time_range
}

fn rule_with<'py>(py: Python<'py>, entries: &[(&str, Bound<'py, PyAny>)]) -> Bound<'py, PyDict> {
    let rule = PyDict::new(py);
    rule.set_item("enable", true).unwrap();
    for (key, value) in entries {
        rule.set_item(key, value).unwrap();
    }
    rule
}

fn parse<'py>(py: Python<'py>, rules: &[Bound<'py, PyAny>]) -> PyResult<Vec<BACnetAccessRule>> {
    access_rules_from_py(PyList::new(py, rules).unwrap().as_any(), "rules")
}

#[test]
fn access_rule_mappings_fill_the_rule_and_default_to_always_and_all() {
    Python::initialize();
    Python::attach(|py| {
        let remote_time_range = schedule_time_range(py);
        remote_time_range
            .set_item("property_array_index", 3)
            .unwrap();
        remote_time_range
            .set_item("device_identifier", py_oid(py, ObjectType::DEVICE, 99))
            .unwrap();
        let pair = PyTuple::new(
            py,
            [
                py_oid(py, ObjectType::DEVICE, 99),
                py_oid(py, ObjectType::ACCESS_ZONE, 3),
            ],
        )
        .unwrap();
        let full = rule_with(
            py,
            &[
                ("time_range", remote_time_range.into_any()),
                ("location", pair.into_any()),
            ],
        );
        let local = rule_with(
            py,
            &[
                ("time_range", schedule_time_range(py).into_any()),
                ("location", py_oid(py, ObjectType::ACCESS_POINT, 2)),
            ],
        );
        // Absent and None both stand for ALWAYS and ALL.
        let open = PyDict::new(py);
        open.set_item("enable", false).unwrap();
        let nones = rule_with(
            py,
            &[
                ("time_range", py.None().into_bound(py)),
                ("location", py.None().into_bound(py)),
            ],
        );

        let parsed = parse(
            py,
            &[
                full.into_any(),
                local.into_any(),
                open.into_any(),
                nones.into_any(),
            ],
        )
        .unwrap();
        assert_eq!(
            parsed[0],
            BACnetAccessRule::new(
                Some(
                    BACnetDeviceObjectPropertyReference::new_remote(
                        oid(ObjectType::SCHEDULE, 1),
                        PropertyIdentifier::PRESENT_VALUE.to_raw(),
                        oid(ObjectType::DEVICE, 99),
                    )
                    .with_index(3)
                ),
                Some(BACnetDeviceObjectReference {
                    device_identifier: Some(oid(ObjectType::DEVICE, 99)),
                    object_identifier: oid(ObjectType::ACCESS_ZONE, 3),
                }),
                true,
            )
        );
        assert_eq!(
            parsed[1],
            BACnetAccessRule::new(
                Some(BACnetDeviceObjectPropertyReference::new_local(
                    oid(ObjectType::SCHEDULE, 1),
                    PropertyIdentifier::PRESENT_VALUE.to_raw(),
                )),
                Some(oid(ObjectType::ACCESS_POINT, 2).into()),
                true,
            )
        );
        for (open, enable) in [(&parsed[2], false), (&parsed[3], true)] {
            assert_eq!(
                open.time_range_specifier,
                AccessRuleTimeRangeSpecifier::ALWAYS
            );
            assert_eq!(open.location_specifier, AccessRuleLocationSpecifier::ALL);
            assert_eq!((&open.time_range, &open.location), (&None, &None));
            assert_eq!(open.enable, enable);
        }
    });
}

#[test]
fn access_rule_mappings_refuse_wrong_shapes_and_non_device_devices() {
    Python::initialize();
    Python::attach(|py| {
        // Not a list at all.
        let error = access_rules_from_py(&3_i32.into_pyobject(py).unwrap().into_any(), "rules")
            .unwrap_err();
        assert!(error.is_instance_of::<PyTypeError>(py), "{error}");

        let not_a_device = || py_oid(py, ObjectType::ANALOG_VALUE, 99);
        let point = || py_oid(py, ObjectType::ACCESS_POINT, 2);
        let type_errors: Vec<Bound<'_, PyAny>> = vec![
            // An element that isn't a mapping.
            point(),
            // An enable flag that isn't a bool.
            {
                let rule = rule_with(py, &[]);
                rule.set_item("enable", 1).unwrap();
                rule.into_any()
            },
            // A time range that isn't a mapping.
            rule_with(py, &[("time_range", point())]).into_any(),
            // A property identifier given as a number.
            {
                let time_range = schedule_time_range(py);
                time_range.set_item("property_identifier", 85).unwrap();
                rule_with(py, &[("time_range", time_range.into_any())]).into_any()
            },
            // A location that is neither form.
            rule_with(
                py,
                &[("location", "door".into_pyobject(py).unwrap().into_any())],
            )
            .into_any(),
        ];
        for rule in type_errors {
            let error = parse(py, std::slice::from_ref(&rule)).unwrap_err();
            assert!(error.is_instance_of::<PyTypeError>(py), "{rule}: {error}");
        }

        let value_errors: Vec<Bound<'_, PyAny>> = vec![
            // No enable flag.
            PyDict::new(py).into_any(),
            // An unknown key.
            rule_with(py, &[("priority", point())]).into_any(),
            // A time range without its property.
            {
                let time_range = schedule_time_range(py);
                time_range.del_item("property_identifier").unwrap();
                rule_with(py, &[("time_range", time_range.into_any())]).into_any()
            },
            // A device member that isn't a Device, in either reference.
            {
                let time_range = schedule_time_range(py);
                time_range
                    .set_item("device_identifier", not_a_device())
                    .unwrap();
                rule_with(py, &[("time_range", time_range.into_any())]).into_any()
            },
            rule_with(
                py,
                &[(
                    "location",
                    PyTuple::new(py, [not_a_device(), point()])
                        .unwrap()
                        .into_any(),
                )],
            )
            .into_any(),
        ];
        for rule in value_errors {
            let error = parse(py, std::slice::from_ref(&rule)).unwrap_err();
            assert!(error.is_instance_of::<PyValueError>(py), "{rule}: {error}");
        }

        // The error names the element and member at fault.
        let bad = rule_with(
            py,
            &[("location", "door".into_pyobject(py).unwrap().into_any())],
        );
        let error = parse(py, &[rule_with(py, &[]).into_any(), bad.into_any()]).unwrap_err();
        assert!(error.to_string().contains("rules[1].location"), "{error}");
    });
}
