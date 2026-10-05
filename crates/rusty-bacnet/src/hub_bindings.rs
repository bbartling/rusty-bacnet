//! Python owns copies of native validated policy, never a peer identity.
use bacnet_transport::sc_hub::{ScHubCertificateBinding, ScHubCertificateBindings};
use pyo3::{
    exceptions::PyValueError,
    prelude::*,
    types::{PyBytes, PyTuple},
};

/// Immutable installation group; routine representation is redacted.
#[pyclass(
    name = "ScHubCertificateBinding",
    module = "rusty_bacnet",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyScHubCertificateBinding {
    inner: ScHubCertificateBinding,
}

#[pymethods]
impl PyScHubCertificateBinding {
    #[new]
    #[pyo3(signature = (*, uuid, allowed_vmacs, leaf_sha256))]
    fn new(
        uuid: Vec<u8>,
        allowed_vmacs: Vec<Vec<u8>>,
        leaf_sha256: Vec<Vec<u8>>,
    ) -> PyResult<Self> {
        let uuid = uuid
            .try_into()
            .map_err(|_| PyValueError::new_err("uuid must be exactly 16 bytes"))?;
        let vmacs = allowed_vmacs
            .into_iter()
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| PyValueError::new_err("each allowed VMAC must be exactly 6 bytes"))
            })
            .collect::<PyResult<Vec<_>>>()?;
        let leaves = leaf_sha256
            .into_iter()
            .map(|value| {
                value.try_into().map_err(|_| {
                    PyValueError::new_err("each leaf SHA-256 digest must be exactly 32 bytes")
                })
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Self {
            inner: ScHubCertificateBinding::new(uuid, vmacs, leaves).map_err(value_error)?,
        })
    }
    #[getter]
    fn uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.uuid())
    }
    #[getter]
    fn allowed_vmacs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(
            py,
            self.inner
                .allowed_vmacs()
                .iter()
                .map(|value| PyBytes::new(py, value)),
        )
    }
    #[getter]
    fn leaf_sha256<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(
            py,
            self.inner
                .leaf_sha256()
                .iter()
                .map(|value| PyBytes::new(py, value)),
        )
    }
    fn __repr__(&self) -> &'static str {
        "ScHubCertificateBinding(<redacted>)"
    }
}
fn value_error(error: bacnet_types::error::Error) -> PyErr {
    PyValueError::new_err(error.to_string())
}

pub(crate) fn bindings(
    groups: Option<Vec<PyRef<'_, PyScHubCertificateBinding>>>,
    hub_vmac: [u8; 6],
) -> PyResult<Option<ScHubCertificateBindings>> {
    groups
        .map(|groups| {
            let bindings = ScHubCertificateBindings::new(
                groups
                    .into_iter()
                    .map(|group| group.inner.clone())
                    .collect(),
            )
            .map_err(value_error)?;
            bindings.validate_hub_vmac(hub_vmac).map_err(value_error)?;
            Ok(bindings)
        })
        .transpose()
}
