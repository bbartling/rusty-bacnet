//! The result of reading one referenced property (`BACnetPropertyAccessResult`,
//! Clause 21): the element type of a Global Group's Present_Value array
//! (Clause 12.50.7).

use super::BACnetDeviceObjectPropertyReference;
use crate::enums::{ErrorClass, ErrorCode};
use crate::primitives::PropertyValue;

/// What reading one property produced: the value, or the error the read
/// failed with (the `access-result` choice of `BACnetPropertyAccessResult`).
///
/// On the wire the value sits inside context tag `[4]` and the error, an
/// application-tagged class then code, inside context tag `[5]`.
#[derive(Debug, Clone, PartialEq)]
pub enum AccessResult {
    /// The value the read returned.
    Value(PropertyValue),
    /// The read failed with this error.
    Error {
        /// The error class.
        class: ErrorClass,
        /// The error code.
        code: ErrorCode,
    },
}

impl AccessResult {
    /// PROPERTY / VALUE_NOT_INITIALIZED: what a Global Group holds for a
    /// member whose value it has not acquired yet (Clause 12.50.7.1).
    pub const NOT_INITIALIZED: Self = Self::Error {
        class: ErrorClass::PROPERTY,
        code: ErrorCode::VALUE_NOT_INITIALIZED,
    };
}

/// A property reference together with what reading it produced
/// (`BACnetPropertyAccessResult`, Clause 21).
///
/// The reference goes out exactly as a [`BACnetDeviceObjectPropertyReference`]
/// does, context tags `[0]` to `[3]` with the array index and the device
/// optional, and the [`AccessResult`] follows. The codec is
/// `bacnet_encoding::constructed::{encode_property_access_result,
/// decode_property_access_result}`.
#[derive(Debug, Clone, PartialEq)]
pub struct BACnetPropertyAccessResult {
    /// The property that was read.
    pub reference: BACnetDeviceObjectPropertyReference,
    /// What the read produced.
    pub access_result: AccessResult,
}
