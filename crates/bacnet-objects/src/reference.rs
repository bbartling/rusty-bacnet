//! Read values and write decoding for the reference properties built on
//! `BACnetObjectPropertyReference` (Clause 21): Loop
//! Manipulated_Variable_Reference and Controlled_Variable_Reference (Clauses
//! 12.17.12 and 12.17.13), Loop Setpoint_Reference (12.17.16), whose
//! `BACnetSetpointReference` wraps one such reference, and Pulse Converter
//! Input_Reference (12.23.6). The device-qualified references, the Averaging
//! Object_Property_Reference among them, go through `device_reference.rs`
//! instead (#1313).
//!
//! The Loop and Pulse Converter serve each reference as
//! `PropertyValue::ApplicationData` holding its context-tagged encoding, built
//! by the shared codecs in `bacnet_encoding::constructed`, and take writes in
//! that encoding (#1312). A bare reference has no empty encoding, so an unset
//! one reads as the standard unset form, the property's usual object type at
//! the reserved instance 4194303 (Clause 12.1, #1417), and writing a
//! reference to that instance clears it, as on Averaging. A
//! `BACnetSetpointReference` does have an empty encoding: its only member is
//! optional and an absent member encodes as nothing (Clause 20.2.16). An
//! unset Setpoint_Reference therefore reads as an empty `ApplicationData`,
//! and writing a value with no octets clears it. Null is a value of another
//! datatype on all four, which the bundled server turns into the success
//! that changes nothing (Clause 15.9.2, #1396).
//!
//! Any other written value holds one reference and is decoded by
//! `common::decode_single_element`, the decoder behind the device references'
//! single-reference rule (#1395; the codes are listed in
//! [`crate::device_reference`]), with the shared offset-taking codecs as its
//! element decoders, so that decoder alone judges what follows the reference
//! (#1414). Another kind of value, a list mixing raw chunks with decoded
//! values, or octets that don't open the way the property's datatype does is
//! PROPERTY / INVALID_DATA_TYPE. Octets that open right but aren't exactly
//! one whole reference (none, one cut short, or anything after it) are
//! PROPERTY / INVALID_DATA_ENCODING. The production has no device-qualifying
//! member \[3\]; the codec refuses one, so it draws the same code as other
//! octets after the reference.

use bacnet_encoding::constructed::{
    decode_object_property_reference_at, decode_setpoint_reference_at,
    encode_object_property_reference, encode_setpoint_reference,
};
use bacnet_encoding::tags::Tag;
use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;
use bytes::BytesMut;

use crate::{common, device_reference};

/// The datatype a reference property is declared with, which fixes how its
/// encoding opens and what stands for "no reference".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReferenceFrame {
    /// `BACnetObjectPropertyReference`: the members alone, opening with the
    /// object identifier's primitive context tag 0 (Loop
    /// Controlled_Variable_Reference and Manipulated_Variable_Reference,
    /// Pulse Converter Input_Reference). A reference to the reserved
    /// instance stands for no reference.
    Bare,
    /// `BACnetSetpointReference`: the members inside opening and closing
    /// context tag 0, or no octets at all for no reference (Loop
    /// Setpoint_Reference).
    Setpoint,
}

/// The unset form of a `BACnetObjectPropertyReference` property (#1417):
/// the Present_Value of `object_type` at the reserved instance 4194303, as
/// [`device_reference::unset_reference`] builds it for the device-qualified
/// references.
pub(crate) fn unset_reference(object_type: ObjectType) -> BACnetObjectPropertyReference {
    BACnetObjectPropertyReference::new(
        device_reference::unset_identifier(object_type),
        PropertyIdentifier::PRESENT_VALUE.to_raw(),
    )
}

/// `reference`, or `None` when it is the unset form, which these properties
/// store as no reference at all.
pub(crate) fn set_or_unset(
    reference: BACnetObjectPropertyReference,
) -> Option<BACnetObjectPropertyReference> {
    (!reference.is_unset()).then_some(reference)
}

/// A `BACnetObjectPropertyReference` property as a read serves it: the
/// reference's context-tagged members, or [`unset_reference`] naming
/// `unset_type` when there is none.
pub(crate) fn object_property_reference_value(
    reference: Option<&BACnetObjectPropertyReference>,
    unset_type: ObjectType,
) -> PropertyValue {
    let mut encoded = BytesMut::new();
    match reference {
        Some(reference) => encode_object_property_reference(&mut encoded, reference),
        None => encode_object_property_reference(&mut encoded, &unset_reference(unset_type)),
    }
    PropertyValue::ApplicationData(encoded.to_vec())
}

/// Setpoint_Reference as a read serves it: the reference framed in context
/// tag 0, or no octets when there is none.
pub(crate) fn setpoint_reference_value(
    reference: Option<&BACnetObjectPropertyReference>,
) -> PropertyValue {
    let mut encoded = BytesMut::new();
    if let Some(reference) = reference {
        encode_setpoint_reference(&mut encoded, reference);
    }
    PropertyValue::ApplicationData(encoded.to_vec())
}

/// Decode a written reference property: `Some(reference)`, or `None` to
/// clear it. See the module documentation for the accepted values and the
/// error each refusal carries.
pub(crate) fn decode_reference_write(
    value: &PropertyValue,
    frame: ReferenceFrame,
) -> Result<Option<BACnetObjectPropertyReference>, Error> {
    match frame {
        ReferenceFrame::Bare => {
            common::decode_single_element(value, opens_bare, decode_object_property_reference_at)
                .map(set_or_unset)
        }
        ReferenceFrame::Setpoint => {
            if common::chunks(value)?.iter().all(|chunk| chunk.is_empty()) {
                return Ok(None);
            }
            common::decode_single_element(value, opens_setpoint, decode_setpoint_reference_at)
                .map(Some)
        }
    }
}

/// The bare members open with the object identifier's primitive context
/// tag 0.
fn opens_bare(tag: &Tag) -> bool {
    tag.is_context(0)
}

/// The setpoint frame opens with opening tag 0.
fn opens_setpoint(tag: &Tag) -> bool {
    tag.is_opening_tag(0)
}

#[cfg(test)]
mod tests;
