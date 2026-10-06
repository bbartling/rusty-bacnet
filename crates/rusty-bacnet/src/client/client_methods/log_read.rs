use super::super::*;

/// The started client, or RuntimeError outside `async with`.
async fn started(
    inner: &ClientInner,
) -> PyResult<Arc<client::BACnetClient<AnyTransport<crate::mstp_py::PySerial>>>> {
    let guard = inner.lock().await;
    guard
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| PyRuntimeError::new_err("client not started — use 'async with'"))
}

#[pymethods]
impl BACnetClient {
    /// Read a range of items from a list or log object.
    ///
    /// `range_type` is `"position"`, `"sequence"`, `"time"` (with
    /// `reference_time`) or `None` (no range); `validation` is `"strict"` or
    /// `"lenient"`.
    #[pyo3(signature = (address, object_id, property_id, array_index=None, range_type=None, reference_index=None, reference_seq=None, count=None, *, reference_time=None, validation="strict"))]
    fn read_range<'py>(
        &self,
        py: Python<'py>,
        address: String,
        object_id: PyObjectIdentifier,
        property_id: PyPropertyIdentifier,
        array_index: Option<u32>,
        range_type: Option<String>,
        reference_index: Option<u64>,
        reference_seq: Option<u64>,
        count: Option<i16>,
        reference_time: Option<Bound<'py, PyAny>>,
        validation: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let request = crate::read_range::request(
            &object_id,
            &property_id,
            array_index,
            range_type.as_deref(),
            reference_index,
            reference_seq,
            count,
            reference_time.as_ref(),
        )?;
        let validation = crate::read_range::validation(validation)?;

        crate::py_async::future_into_py(py, async move {
            let mac = parse_address(&address)?;
            let c = started(&inner).await?;
            let reply = c
                .read_range_with(&mac, &request, validation)
                .await
                .map_err(to_py_err)?;
            crate::py_async::attach(|py| crate::read_range::reply_to_dict(py, reply))
        })
    }

    /// Read one page of a log's Log_Buffer from `cursor` (None for the
    /// oldest record), up to `page_size` records.
    #[pyo3(signature = (address, object_id, cursor=None, page_size=100))]
    fn read_log_page<'py>(
        &self,
        py: Python<'py>,
        address: String,
        object_id: PyObjectIdentifier,
        cursor: Option<Bound<'py, PyAny>>,
        page_size: u32,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (log, cursor, page_size) =
            crate::log_records::page_request(&object_id, cursor.as_ref(), page_size)?;

        crate::py_async::future_into_py(py, async move {
            let mac = parse_address(&address)?;
            let c = started(&inner).await?;
            let page = c
                .read_log_page(&mac, log, cursor, page_size)
                .await
                .map_err(to_py_err)?;
            crate::py_async::attach(|py| crate::log_records::page_to_py(py, page))
        })
    }
}
