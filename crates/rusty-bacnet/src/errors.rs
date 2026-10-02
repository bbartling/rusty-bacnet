//! Python exception types mapping Rust BACnet errors.

use bacnet_types::error::Error;
use pyo3::create_exception;
use pyo3::prelude::*;

// Exception hierarchy: BacnetError (base) with subtypes
create_exception!(rusty_bacnet, BacnetError, pyo3::exceptions::PyException);
create_exception!(rusty_bacnet, BacnetProtocolError, BacnetError);
create_exception!(rusty_bacnet, BacnetTimeoutError, BacnetError);
create_exception!(rusty_bacnet, BacnetRejectError, BacnetError);
create_exception!(rusty_bacnet, BacnetAbortError, BacnetError);

/// Convert a Rust `Error` into a Python exception.
///
/// Protocol errors, rejects, and aborts carry structured integer attributes
/// (`error_class`/`error_code` or `reason`) so Python callers can inspect them
/// programmatically without parsing the message string. A protocol error also
/// carries `first_failed_element_number`: the element position from an
/// AddListElement or RemoveListElement ChangeList-Error, `None` otherwise.
/// Futures call this on binding threads, so the attributes are set through
/// the exit gate (#1002).
pub fn to_py_err(err: Error) -> PyErr {
    match err {
        Error::Protocol { class, code } => protocol_error(
            format!("BACnet error: class={class} code={code}"),
            class,
            code,
            None,
        ),
        Error::ChangeList {
            class,
            code,
            first_failed_element_number,
        } => protocol_error(
            format!(
                "BACnet error: class={class} code={code} \
                 first_failed_element_number={first_failed_element_number}"
            ),
            class,
            code,
            Some(first_failed_element_number),
        ),
        Error::Timeout(_) => BacnetTimeoutError::new_err(err.to_string()),
        Error::Reject { reason } => {
            let py_err = BacnetRejectError::new_err(format!("BACnet reject: reason={reason}"));
            let _ = crate::py_async::attach(|py| {
                let val = py_err.value(py);
                let _ = val.setattr("reason", reason);
                Ok(())
            });
            py_err
        }
        Error::Abort { reason } => {
            let py_err = BacnetAbortError::new_err(format!("BACnet abort: reason={reason}"));
            let _ = crate::py_async::attach(|py| {
                let val = py_err.value(py);
                let _ = val.setattr("reason", reason);
                Ok(())
            });
            py_err
        }
        _ => BacnetError::new_err(err.to_string()),
    }
}

fn protocol_error(
    message: String,
    class: u32,
    code: u32,
    first_failed_element_number: Option<u32>,
) -> PyErr {
    let py_err = BacnetProtocolError::new_err(message);
    let _ = crate::py_async::attach(|py| {
        let val = py_err.value(py);
        let _ = val.setattr("error_class", class);
        let _ = val.setattr("error_code", code);
        let _ = val.setattr("first_failed_element_number", first_failed_element_number);
        Ok(())
    });
    py_err
}

/// Register exception types with the module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("BacnetError", m.py().get_type::<BacnetError>())?;
    m.add(
        "BacnetProtocolError",
        m.py().get_type::<BacnetProtocolError>(),
    )?;
    m.add(
        "BacnetTimeoutError",
        m.py().get_type::<BacnetTimeoutError>(),
    )?;
    m.add("BacnetRejectError", m.py().get_type::<BacnetRejectError>())?;
    m.add("BacnetAbortError", m.py().get_type::<BacnetAbortError>())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_errors_carry_the_first_failed_element_number() {
        Python::initialize();
        Python::attach(|py| {
            let number = |error: &PyErr, name: &str| -> Option<u32> {
                error.value(py).getattr(name).unwrap().extract().unwrap()
            };
            // SERVICES / LIST_ELEMENT_NOT_FOUND at element 2 (#1026).
            let change_list = to_py_err(Error::ChangeList {
                class: 5,
                code: 81,
                first_failed_element_number: 2,
            });
            assert!(change_list.is_instance_of::<BacnetProtocolError>(py));
            assert_eq!(number(&change_list, "error_class"), Some(5));
            assert_eq!(number(&change_list, "error_code"), Some(81));
            assert_eq!(number(&change_list, "first_failed_element_number"), Some(2));

            let plain = to_py_err(Error::Protocol { class: 2, code: 31 });
            assert!(plain.is_instance_of::<BacnetProtocolError>(py));
            assert_eq!(number(&plain, "error_code"), Some(31));
            assert_eq!(number(&plain, "first_failed_element_number"), None);
        });
    }
}
