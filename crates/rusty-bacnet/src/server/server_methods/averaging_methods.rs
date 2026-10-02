//! The application route that feeds a stored Averaging object (#1083).
use super::super::*;

#[pymethods]
impl BACnetServer {
    /// Record one sample of an Averaging object's referenced property, taken
    /// by the application; the server doesn't read the reference itself.
    ///
    /// The value is a BOOLEAN (0 or 1), Signed, Unsigned, Enumerated or finite
    /// REAL. Another datatype raises INVALID_DATA_TYPE and NaN or an infinity
    /// VALUE_OUT_OF_RANGE. Any object other than an Averaging object raises
    /// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, as in `set_present_value_local`.
    /// The statistics change together and go through the server's COV path:
    /// a SubscribeCOVProperty on one of them is notified, while SubscribeCOV
    /// on an Averaging object is refused.
    #[pyo3(signature = (object_id, value))]
    fn add_averaging_sample_local<'py>(
        &self,
        py: Python<'py>,
        object_id: PyObjectIdentifier,
        value: PyPropertyValue,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let oid = object_id.to_rust();
        let prop_value = value.inner;

        let future = async move {
            let guard = inner.lock().await;
            let srv = guard
                .as_ref()
                .ok_or_else(|| PyRuntimeError::new_err("server not started"))?;
            srv.add_averaging_sample_local(&oid, prop_value)
                .await
                .map_err(to_py_err)
        };
        crate::py_async::future_into_py(py, crate::unit_result(future))
    }
}
