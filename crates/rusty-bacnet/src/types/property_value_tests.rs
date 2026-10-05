use super::*;

/// A null wrapped in `depth` lists, built as `PropertyValue.list` builds it.
fn nested(depth: usize) -> PyResult<PyPropertyValue> {
    let mut value = PyPropertyValue::null();
    for _ in 0..depth {
        value = PyPropertyValue::list(vec![value])?;
    }
    Ok(value)
}

#[test]
fn lists_nest_as_deep_as_the_decoder_allows_and_no_deeper() {
    Python::initialize();
    let deepest = nested(MAX_CONTEXT_NESTING_DEPTH).unwrap();
    assert_eq!(list_depth(&deepest.inner), 32);
    // 32 deep through its second item.
    let deep_second =
        PyPropertyValue::list(vec![PyPropertyValue::null(), nested(31).unwrap()]).unwrap();
    assert_eq!(list_depth(&deep_second.inner), 32);
    let refused = [
        vec![deepest.clone()],
        // The deepest item counts, wherever it sits.
        vec![
            PyPropertyValue::null(),
            deepest,
            PyPropertyValue::list(vec![]).unwrap(),
        ],
        vec![deep_second],
    ];
    for items in refused {
        let err = PyPropertyValue::list(items).unwrap_err();
        Python::attach(|py| {
            assert!(err.is_instance_of::<PyValueError>(py));
            assert_eq!(err.value(py).to_string(), "lists nest at most 32 deep");
        });
    }
}

#[test]
fn equal_values_hash_alike() {
    let floats = [0.0, -0.0, f64::NAN, -f64::NAN, 1.0, -1.0, f64::INFINITY];
    let mut values: Vec<PyPropertyValue> = floats
        .iter()
        .flat_map(|&float| {
            [
                PyPropertyValue::real(float as f32),
                PyPropertyValue::double(float),
            ]
        })
        .collect();
    let lists: Vec<PyPropertyValue> = values
        .iter()
        .map(|value| PyPropertyValue::list(vec![value.clone()]).unwrap())
        .collect();
    values.extend(lists);
    for a in &values {
        for b in &values {
            if a == b {
                assert_eq!(a.__hash__(), b.__hash__(), "{a:?} == {b:?}");
            }
        }
    }
    // Signed zero is one value, so the check above covers it.
    assert_eq!(PyPropertyValue::real(0.0), PyPropertyValue::real(-0.0));
    assert_eq!(PyPropertyValue::double(0.0), PyPropertyValue::double(-0.0));
}
