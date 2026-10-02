//! Python exception types mapping Rust BACnet errors.

use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::{Error, ErrorDetail};
use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::types::{PyObjectIdentifier, PyPropertyIdentifier};

// Exception hierarchy: BacnetError (base) with subtypes
create_exception!(rusty_bacnet, BacnetError, pyo3::exceptions::PyException);
create_exception!(rusty_bacnet, BacnetProtocolError, BacnetError);
create_exception!(rusty_bacnet, BacnetTimeoutError, BacnetError);
create_exception!(rusty_bacnet, BacnetRejectError, BacnetError);
create_exception!(rusty_bacnet, BacnetAbortError, BacnetError);

/// The `BacnetProtocolError` attributes a structured Clause 21 error body
/// fills in. Each is `None` unless the body carried it, including on the
/// class itself.
const DETAIL_ATTRIBUTES: [&str; 7] = [
    "first_failed_element_number",
    "first_failed_write_attempt",
    "first_failed_subscription",
    "vendor_id",
    "service_number",
    "error_parameters",
    "vt_session_identifiers",
];

/// Convert a Rust `Error` into a Python exception.
///
/// Protocol errors, rejects, and aborts carry structured integer attributes
/// (`error_class`/`error_code` or `reason`) so Python callers can inspect them
/// programmatically without parsing the message string. A protocol error also
/// carries what a structured error body adds, `None` when absent:
/// `first_failed_element_number` (ChangeList-Error, CreateObject-Error),
/// `first_failed_write_attempt` (WritePropertyMultiple-Error) and
/// `first_failed_subscription` (SubscribeCOVPropertyMultiple-Error) as
/// object/property/index dicts, `vendor_id`, `service_number` and
/// `error_parameters` (ConfirmedPrivateTransfer-Error), and
/// `vt_session_identifiers` (VTClose-Error). Futures call this on binding
/// threads, so the attributes are set through the exit gate (#1002).
pub fn to_py_err(err: Error) -> PyErr {
    match err {
        Error::Protocol { class, code } => protocol_error(
            format!("BACnet error: class={class} code={code}"),
            class,
            code,
            None,
        ),
        Error::Structured {
            class,
            code,
            detail,
        } => protocol_error(
            format!("BACnet error: class={class} code={code}, {detail}"),
            class,
            code,
            Some(*detail),
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

fn protocol_error(message: String, class: u32, code: u32, detail: Option<ErrorDetail>) -> PyErr {
    let py_err = BacnetProtocolError::new_err(message);
    let _ = crate::py_async::attach(|py| {
        let val = py_err.value(py);
        let _ = val.setattr("error_class", class);
        let _ = val.setattr("error_code", code);
        for name in DETAIL_ATTRIBUTES {
            let _ = val.setattr(name, py.None());
        }
        if let Some(detail) = &detail {
            let _ = set_detail(py, val.as_any(), detail);
        }
        Ok(())
    });
    py_err
}

fn set_detail(py: Python<'_>, error: &Bound<'_, PyAny>, detail: &ErrorDetail) -> PyResult<()> {
    match detail {
        ErrorDetail::FirstFailedElementNumber(number) => {
            error.setattr("first_failed_element_number", number)
        }
        ErrorDetail::FirstFailedWriteAttempt(attempt) => {
            error.setattr("first_failed_write_attempt", reference(py, attempt)?)
        }
        ErrorDetail::FirstFailedSubscription(subscription) => {
            error.setattr("first_failed_subscription", reference(py, subscription)?)
        }
        ErrorDetail::PrivateTransfer {
            vendor_id,
            service_number,
            error_parameters,
        } => {
            error.setattr("vendor_id", vendor_id)?;
            error.setattr("service_number", service_number)?;
            error.setattr(
                "error_parameters",
                error_parameters
                    .as_deref()
                    .map(|parameters| PyBytes::new(py, parameters)),
            )
        }
        ErrorDetail::VtSessionIdentifiers(sessions) => {
            error.setattr("vt_session_identifiers", PyList::new(py, sessions.iter())?)
        }
    }
}

/// `{"object_identifier", "property_identifier", "property_array_index"}`.
fn reference<'py>(
    py: Python<'py>,
    reference: &BACnetObjectPropertyReference,
) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item(
        "object_identifier",
        PyObjectIdentifier::from_rust(reference.object_identifier),
    )?;
    result.set_item(
        "property_identifier",
        PyPropertyIdentifier {
            inner: PropertyIdentifier::from_raw(reference.property_identifier),
        },
    )?;
    result.set_item("property_array_index", reference.property_array_index)?;
    Ok(result)
}

/// Register exception types with the module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("BacnetError", m.py().get_type::<BacnetError>())?;
    let protocol = m.py().get_type::<BacnetProtocolError>();
    for name in DETAIL_ATTRIBUTES {
        protocol.setattr(name, m.py().None())?;
    }
    m.add("BacnetProtocolError", protocol)?;
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
    use bacnet_types::enums::ObjectType;
    use bacnet_types::primitives::ObjectIdentifier;

    #[test]
    fn protocol_errors_carry_their_structured_detail() {
        Python::initialize();
        Python::attach(|py| {
            let number = |error: &PyErr, name: &str| -> Option<u32> {
                error.value(py).getattr(name).unwrap().extract().unwrap()
            };
            let none = |error: &PyErr, name: &str| error.value(py).getattr(name).unwrap().is_none();
            // SERVICES / LIST_ELEMENT_NOT_FOUND at element 2 (#1026).
            let change_list = to_py_err(Error::protocol(
                5,
                81,
                Some(ErrorDetail::FirstFailedElementNumber(2)),
            ));
            assert!(change_list.is_instance_of::<BacnetProtocolError>(py));
            assert_eq!(number(&change_list, "error_class"), Some(5));
            assert_eq!(number(&change_list, "error_code"), Some(81));
            assert_eq!(number(&change_list, "first_failed_element_number"), Some(2));
            assert!(none(&change_list, "vendor_id"));

            let plain = to_py_err(Error::Protocol { class: 2, code: 31 });
            assert!(plain.is_instance_of::<BacnetProtocolError>(py));
            assert_eq!(number(&plain, "error_code"), Some(31));
            assert_eq!(number(&plain, "first_failed_element_number"), None);

            // #1047: the other bodies.
            let write = to_py_err(Error::protocol(
                2,
                40,
                Some(ErrorDetail::FirstFailedWriteAttempt(
                    BACnetObjectPropertyReference::new_indexed(
                        ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 7).unwrap(),
                        PropertyIdentifier::PRESENT_VALUE.to_raw(),
                        3,
                    ),
                )),
            ));
            let attempt = write
                .value(py)
                .getattr("first_failed_write_attempt")
                .unwrap();
            let oid: PyObjectIdentifier = attempt
                .get_item("object_identifier")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(
                oid.to_rust(),
                ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 7).unwrap()
            );
            let index: Option<u32> = attempt
                .get_item("property_array_index")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(index, Some(3));
            assert!(none(&write, "first_failed_subscription"));

            let private = to_py_err(Error::protocol(
                5,
                45,
                Some(ErrorDetail::PrivateTransfer {
                    vendor_id: 555,
                    service_number: 7,
                    error_parameters: Some(vec![0x21, 1]),
                }),
            ));
            assert_eq!(number(&private, "vendor_id"), Some(555));
            assert_eq!(number(&private, "service_number"), Some(7));
            let parameters: Vec<u8> = private
                .value(py)
                .getattr("error_parameters")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(parameters, [0x21, 1]);

            let vt_close = to_py_err(Error::protocol(
                5,
                39,
                Some(ErrorDetail::VtSessionIdentifiers(vec![1, 4])),
            ));
            let sessions: Vec<u32> = vt_close
                .value(py)
                .getattr("vt_session_identifiers")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(sessions, [1, 4]);
        });
    }
}
