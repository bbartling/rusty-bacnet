//! Strict readers for the mapping-shaped arguments the binding takes: every
//! key is checked against the allowed set, every value is type-checked, and
//! each error names the field it came from.
//!
//! An integer is read as the fixed-width type of the field it fills, and one
//! outside that type raises OverflowError, as pyo3 raises for a parameter of
//! that type, so the same value fails the same way however it is passed
//! (#1360). A narrower range BACnet sets for a value that fits is the
//! binding's ValueError, or the object's BacnetProtocolError.

use std::fmt::Display;
use std::ops::RangeInclusive;

use bacnet_types::constructed::BACnetScale;
use bacnet_types::primitives::ObjectIdentifier;
use pyo3::exceptions::{PyOverflowError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyFloat, PyInt, PyMapping, PyString};

use super::PyObjectIdentifier;

pub(crate) fn mapping<'a, 'py>(
    value: &'a Bound<'py, PyAny>,
    name: &str,
) -> PyResult<&'a Bound<'py, PyMapping>> {
    value
        .cast::<PyMapping>()
        .map_err(|_| PyTypeError::new_err(format!("{name} must be a mapping")))
}

pub(crate) fn validate_keys(
    value: &Bound<'_, PyMapping>,
    name: &str,
    required: &[&str],
    optional: &[&str],
) -> PyResult<()> {
    for key in value.keys()?.iter() {
        if key.cast::<PyString>().is_err() {
            return Err(PyTypeError::new_err(format!(
                "{name} mapping keys must be strings"
            )));
        }
        let key = key.extract::<String>()?;
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(PyValueError::new_err(format!(
                "{name} contains unknown key '{key}'"
            )));
        }
    }
    for &key in required {
        if !value.contains(key)? {
            return Err(PyValueError::new_err(format!(
                "{name} is missing required key '{key}'"
            )));
        }
    }
    Ok(())
}

pub(crate) fn required_item<'py>(
    value: &Bound<'py, PyMapping>,
    name: &str,
    key: &str,
) -> PyResult<Bound<'py, PyAny>> {
    if !value.contains(key)? {
        return Err(PyValueError::new_err(format!(
            "{name} is missing required key '{key}'"
        )));
    }
    value.get_item(key)
}

pub(crate) fn optional_item<'py>(
    value: &Bound<'py, PyMapping>,
    key: &str,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    if !value.contains(key)? {
        return Ok(None);
    }
    let item = value.get_item(key)?;
    Ok((!item.is_none()).then_some(item))
}

pub(crate) fn discriminator(value: &Bound<'_, PyMapping>, name: &str) -> PyResult<String> {
    required_item(value, name, "kind")?
        .extract::<String>()
        .map_err(|_| PyValueError::new_err(format!("{name}.kind must be a valid discriminator")))
}

pub(crate) fn integer(value: &Bound<'_, PyAny>, name: &str) -> PyResult<i128> {
    if value.is_instance_of::<PyBool>() || value.cast::<PyInt>().is_err() {
        return Err(PyTypeError::new_err(format!("{name} must be an integer")));
    }
    value.extract::<i128>().map_err(|_| {
        PyOverflowError::new_err(format!("{name} is outside the supported integer range"))
    })
}

/// A fixed-width integer type a field is read as, with its bounds for the
/// errors to name.
pub(crate) trait FixedWidth: TryFrom<i128> + Copy + PartialOrd + Display {
    /// The smallest value the type holds.
    const MIN: i128;
    /// The largest value the type holds.
    const MAX: i128;
}

macro_rules! fixed_width {
    ($($type:ty),*) => {
        $(impl FixedWidth for $type {
            const MIN: i128 = <$type>::MIN as i128;
            const MAX: i128 = <$type>::MAX as i128;
        })*
    };
}

fixed_width!(u8, u16, u32, u64, i32);

/// `value` as `T`; outside `T` (negative for an unsigned type, or too wide)
/// raises OverflowError naming the range `T` holds.
pub(crate) fn fit<T: FixedWidth>(value: i128, name: &str) -> PyResult<T> {
    T::try_from(value).map_err(|_| {
        PyOverflowError::new_err(format!(
            "{name} must be {}..={}, got {value}",
            T::MIN,
            T::MAX
        ))
    })
}

/// An integer read as `T`, the fixed-width type of the field it fills: a
/// value outside `T` raises OverflowError.
pub(crate) fn fixed_integer<T: FixedWidth>(value: &Bound<'_, PyAny>, name: &str) -> PyResult<T> {
    fit(integer(value, name)?, name)
}

/// An integer read as `T` and then held to `range`, the values BACnet allows
/// in the field: outside `T` raises OverflowError, and a value that fits `T`
/// but not `range` ValueError.
pub(crate) fn ranged_integer<T>(
    value: &Bound<'_, PyAny>,
    name: &str,
    range: RangeInclusive<T>,
) -> PyResult<T>
where
    T: FixedWidth,
{
    let value = fixed_integer::<T>(value, name)?;
    if !range.contains(&value) {
        return Err(PyValueError::new_err(format!(
            "{name} must be {}..={}, got {value}",
            range.start(),
            range.end()
        )));
    }
    Ok(value)
}

pub(crate) fn string(value: &Bound<'_, PyAny>, name: &str) -> PyResult<String> {
    if value.cast::<PyString>().is_err() {
        return Err(PyTypeError::new_err(format!("{name} must be a str")));
    }
    value.extract::<String>()
}

pub(crate) fn bytes(value: &Bound<'_, PyAny>, name: &str) -> PyResult<Vec<u8>> {
    value
        .cast::<PyBytes>()
        .map(|value| value.as_bytes().to_vec())
        .map_err(|_| PyTypeError::new_err(format!("{name} must be bytes")))
}

/// An Accumulator's Scale (#1487): a float is a float scale and an int a
/// power-of-ten scale. A bool or any other type raises TypeError, an int
/// outside INTEGER's 32 bits OverflowError, and a float that isn't finite
/// once rounded to a REAL ValueError.
pub(crate) fn scale(value: &Bound<'_, PyAny>) -> PyResult<BACnetScale> {
    if value.is_instance_of::<PyInt>() && !value.is_instance_of::<PyBool>() {
        return Ok(BACnetScale::IntegerScale(value.extract()?));
    }
    if value.is_instance_of::<PyFloat>() {
        let factor = value.extract::<f64>()? as f32;
        if !factor.is_finite() {
            return Err(PyValueError::new_err(
                "scale must be finite as a single-precision REAL",
            ));
        }
        return Ok(BACnetScale::FloatScale(factor));
    }
    Err(PyTypeError::new_err("scale must be a float or an int"))
}

pub(crate) fn object_identifier(
    value: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<ObjectIdentifier> {
    value
        .extract::<PyObjectIdentifier>()
        .map(|value| value.to_rust())
        .map_err(|_| PyTypeError::new_err(format!("{name} must be an ObjectIdentifier")))
}
