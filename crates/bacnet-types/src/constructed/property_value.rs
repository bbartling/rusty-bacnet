//! A property value with its reference and write priority
//! (`BACnetPropertyValue`, Clause 21): the element of WritePropertyMultiple,
//! CreateObject and COV notification lists, and of a complex event type's
//! notification values.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::enums::PropertyIdentifier;

/// BACnetPropertyValue (Clause 21.6).
///
/// Four context-tagged members in order: property identifier `[0]`, an optional Unsigned array
/// index `[1]`, the value inside an opening/closing `[2]` pair (typed by the property), and an
/// optional priority `[3]`, an Unsigned limited to 1-16.
///
/// The `value` field contains raw application-tagged bytes. The application
/// layer interprets the value based on the property type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BACnetPropertyValue {
    /// Property being reported.
    pub property_identifier: PropertyIdentifier,
    /// Array element index; `None` means the whole property.
    pub property_array_index: Option<u32>,
    /// Property value as encoded BACnet bytes, without the surrounding `[2]` context tags.
    pub value: Vec<u8>,
    /// Write priority (1-16); `None` when absent.
    pub priority: Option<u8>,
}
