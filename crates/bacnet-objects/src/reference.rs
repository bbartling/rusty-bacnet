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
//! one reads Null and a Null write clears it, as Averaging does. A
//! `BACnetSetpointReference` does have one: its only member is optional and
//! an absent member encodes as nothing (Clause 20.2.16). An unset
//! Setpoint_Reference therefore reads as an empty `ApplicationData`, writing
//! the empty value clears it, and Null is a value of another datatype there.
//!
//! A written value is one `ApplicationData` (the octets a WriteProperty
//! carried, which the server hands over whole, or a value read back), or a
//! list of `ApplicationData` chunks that join into one (the same octets split
//! at each member's tag). The flat application-tagged list, any other kind of
//! value, or octets that don't open the way the property's datatype does is
//! PROPERTY / INVALID_DATA_TYPE. Octets that open right but don't decode in
//! full, a list mixing chunks with decoded values, or a device-qualifying
//! member \[3\] on a production without one is PROPERTY /
//! INVALID_DATA_ENCODING.

use bacnet_encoding::constructed::{
    decode_object_property_reference, decode_setpoint_reference, encode_object_property_reference,
    encode_setpoint_reference,
};
use bacnet_encoding::tags;
use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;
use bytes::BytesMut;

use crate::common;

/// The datatype a reference property is declared with, which fixes how its
/// encoding opens and what stands for "no reference".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReferenceFrame {
    /// `BACnetObjectPropertyReference`: the members alone, opening with the
    /// object identifier's primitive context tag 0 (Loop
    /// Controlled_Variable_Reference and Manipulated_Variable_Reference,
    /// Pulse Converter Input_Reference). Null stands for no reference.
    Bare,
    /// `BACnetSetpointReference`: the members inside opening and closing
    /// context tag 0, or no octets at all for no reference (Loop
    /// Setpoint_Reference).
    Setpoint,
}

/// A `BACnetObjectPropertyReference` property as a read serves it: the
/// reference's context-tagged members, or Null when there is none.
pub(crate) fn object_property_reference_value(
    reference: Option<&BACnetObjectPropertyReference>,
) -> PropertyValue {
    let Some(reference) = reference else {
        return PropertyValue::Null;
    };
    let mut encoded = BytesMut::new();
    encode_object_property_reference(&mut encoded, reference);
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
    let joined;
    let bytes: &[u8] = match value {
        PropertyValue::Null if frame != ReferenceFrame::Setpoint => return Ok(None),
        PropertyValue::ApplicationData(bytes) => bytes,
        PropertyValue::List(items)
            if matches!(items.first(), Some(PropertyValue::ApplicationData(_))) =>
        {
            joined = join_chunks(items)?;
            &joined
        }
        _ => return Err(common::invalid_data_type_error()),
    };
    if frame == ReferenceFrame::Setpoint && bytes.is_empty() {
        return Ok(None);
    }
    match tags::decode_tag(bytes, 0) {
        Ok((tag, _)) if frame == ReferenceFrame::Setpoint && tag.is_opening_tag(0) => {}
        Ok((tag, _)) if frame != ReferenceFrame::Setpoint && tag.is_context(0) => {}
        Ok(_) => return Err(common::invalid_data_type_error()),
        Err(_) => return Err(common::invalid_data_encoding_error()),
    }
    match frame {
        ReferenceFrame::Bare => decode_object_property_reference(bytes)
            .map(Some)
            .map_err(|_| common::invalid_data_encoding_error()),
        ReferenceFrame::Setpoint => {
            decode_setpoint_reference(bytes).map_err(|_| common::invalid_data_encoding_error())
        }
    }
}

/// Join a list of `ApplicationData` chunks into one run of octets. A list
/// that mixes chunks with decoded values can't be one encoding:
/// INVALID_DATA_ENCODING.
fn join_chunks(items: &[PropertyValue]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for item in items {
        let PropertyValue::ApplicationData(part) = item else {
            return Err(common::invalid_data_encoding_error());
        };
        bytes.extend_from_slice(part);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
