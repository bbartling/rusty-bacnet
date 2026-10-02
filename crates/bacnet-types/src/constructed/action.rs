//! The elements of a Command object's Action array (Clause 12.10.8):
//! `BACnetActionList` and the `BACnetActionCommand` writes it holds
//! (Clause 21).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::enums::PropertyIdentifier;
use crate::primitives::{ObjectIdentifier, PropertyValue};

/// One write a Command object makes when it runs an action list
/// (`BACnetActionCommand`, Clause 21).
///
/// On the wire every member is context tagged, numbered `[0]` to `[8]` in
/// field order. The device, array index, priority and post delay are
/// optional; the value sits inside an opening/closing tag pair `[4]`. The
/// codec is `bacnet_encoding::constructed::{encode_action_command,
/// decode_action_command}`.
#[derive(Debug, Clone, PartialEq)]
pub struct BACnetActionCommand {
    /// The device holding the target object; `None` for this device.
    pub device_identifier: Option<ObjectIdentifier>,
    /// The object written.
    pub object_identifier: ObjectIdentifier,
    /// The property written.
    pub property_identifier: PropertyIdentifier,
    /// The element written, for an array property; `None` writes it whole.
    pub property_array_index: Option<u32>,
    /// The value written.
    pub property_value: PropertyValue,
    /// The command priority, 1 to 16, for a commandable property.
    pub priority: Option<u8>,
    /// How long to wait after this write before the next one.
    pub post_delay: Option<u32>,
    /// Whether a failed write stops the rest of the list.
    pub quit_on_failure: bool,
    /// Whether the last attempt at this write succeeded.
    pub write_successful: bool,
}

/// One element of a Command object's Action array: the writes taken, in
/// order, when Present_Value selects it (`BACnetActionList`, Clause 21).
///
/// On the wire the commands go back to back inside an opening/closing tag
/// pair `[0]`, so an empty list is that pair alone. The codec is
/// `bacnet_encoding::constructed::{encode_action_list, decode_action_list}`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BACnetActionList {
    /// The writes, in the order they're made.
    pub commands: Vec<BACnetActionCommand>,
}
