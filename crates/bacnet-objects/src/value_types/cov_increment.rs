//! COV_Increment storage for the numeric value types (#1111).
//!
//! Integer Value and Positive Integer Value type their COV_Increment as
//! Unsigned (Tables 12-50 and 12-51) and Large Analog Value as Double
//! (Table 12-46). Footnote 3 of each table makes the row required on an object
//! that reports COV, which every value type here does. The macro stores the
//! table's datatype and goes through this trait for the wire form, validation
//! and the `f64` the server's change detection compares against.

use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use crate::common;

/// A COV_Increment datatype stored by a numeric value object.
pub(super) trait CovIncrement: Copy {
    /// The increment a new object starts with: 0, so any change notifies.
    const ZERO: Self;

    /// Check a value before it is stored.
    fn validate(self) -> Result<Self, Error>;

    /// Encode the stored value in the table's datatype.
    fn to_property(self) -> PropertyValue;

    /// Take a written value, refusing any other datatype.
    fn from_property(value: PropertyValue) -> Result<Self, Error>;

    /// The increment the server's COV change detection uses.
    fn as_f64(self) -> f64;
}

/// Unsigned: every value the decoder yields is a valid increment.
impl CovIncrement for u64 {
    const ZERO: Self = 0;

    fn validate(self) -> Result<Self, Error> {
        Ok(self)
    }

    fn to_property(self) -> PropertyValue {
        PropertyValue::Unsigned(self)
    }

    fn from_property(value: PropertyValue) -> Result<Self, Error> {
        match value {
            PropertyValue::Unsigned(v) => Ok(v),
            _ => Err(common::invalid_data_type_error()),
        }
    }

    fn as_f64(self) -> f64 {
        self as f64
    }
}

/// Double: a negative or non-finite increment has no meaning as a minimum
/// change, so it is refused with VALUE_OUT_OF_RANGE, as Analog Value refuses
/// its REAL one.
impl CovIncrement for f64 {
    const ZERO: Self = 0.0;

    fn validate(self) -> Result<Self, Error> {
        if self.is_finite() && self >= 0.0 {
            Ok(self)
        } else {
            Err(common::value_out_of_range_error())
        }
    }

    fn to_property(self) -> PropertyValue {
        PropertyValue::Double(self)
    }

    fn from_property(value: PropertyValue) -> Result<Self, Error> {
        match value {
            PropertyValue::Double(v) => v.validate(),
            _ => Err(common::invalid_data_type_error()),
        }
    }

    fn as_f64(self) -> f64 {
        self
    }
}
