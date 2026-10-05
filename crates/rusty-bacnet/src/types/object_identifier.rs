use super::*;

use pyo3::types::PyType;

// ---------------------------------------------------------------------------
// ObjectIdentifier
// ---------------------------------------------------------------------------

/// BACnet Object Identifier (type + instance).
///
/// For u32-representable values, types above 1023 or instances above 4,194,303
/// raise ValueError. Integers outside u32 retain their argument-conversion errors.
/// Valid proprietary types and the wire wildcard instance are accepted.
///
/// Usage: `ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)`
///
/// `copy` and `pickle` rebuild one through that constructor (#1500).
#[pyclass(
    name = "ObjectIdentifier",
    module = "rusty_bacnet",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct PyObjectIdentifier {
    inner: primitives::ObjectIdentifier,
}

#[pymethods]
impl PyObjectIdentifier {
    #[new]
    fn new(object_type: &PyObjectType, instance: u32) -> PyResult<Self> {
        let oid = primitives::ObjectIdentifier::new(object_type.to_rust(), instance)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner: oid })
    }

    /// The object type.
    #[getter]
    fn object_type(&self) -> PyObjectType {
        PyObjectType {
            inner: self.inner.object_type(),
        }
    }

    /// The instance number.
    #[getter]
    fn instance(&self) -> u32 {
        self.inner.instance_number()
    }

    fn __repr__(&self) -> String {
        format!(
            "ObjectIdentifier({}, {})",
            self.inner.object_type(),
            self.inner.instance_number()
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        (self.inner.object_type().to_raw() as u64) << 22 | self.inner.instance_number() as u64
    }

    /// What `copy` and `pickle` call: the class and its constructor's
    /// arguments. `__getnewargs__` would serve only pickle protocols 2 and
    /// up; this serves 0 and 1 as well. Every identifier the class holds
    /// (10-bit type, 22-bit instance) passes the constructor's checks.
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> (Bound<'py, PyType>, (PyObjectType, u32)) {
        let oid = slf.get().inner;
        (
            slf.get_type(),
            (
                PyObjectType {
                    inner: oid.object_type(),
                },
                oid.instance_number(),
            ),
        )
    }
}

impl PyObjectIdentifier {
    pub fn to_rust(&self) -> primitives::ObjectIdentifier {
        self.inner
    }

    pub fn from_rust(oid: primitives::ObjectIdentifier) -> Self {
        Self { inner: oid }
    }
}
