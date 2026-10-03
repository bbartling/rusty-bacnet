//! `BACnetObjectPropertyReference` and its `BACnetSetpointReference` wrapper
//! (ASHRAE 135-2020 Clause 21) — wire codecs for the object-reference
//! properties of the Loop (Clause 12.17) and Pulse Converter (Clause 12.23)
//! objects.
//!
//! `BACnetObjectPropertyReference` names one property of an object, and can
//! narrow it to a single element when the property is an array:
//!
//! | Field | Tag | Type | Optional |
//! |---|---|---|---|
//! | `object-identifier` | `[0]` | `BACnetObjectIdentifier` | no |
//! | `property-identifier` | `[1]` | `BACnetPropertyIdentifier` | no |
//! | `property-array-index` | `[2]` | Unsigned | yes; only meaningful for array properties |
//!
//! `BACnetSetpointReference` wraps at most one such reference:
//!
//! | Field | Tag | Type | Optional |
//! |---|---|---|---|
//! | `setpoint-reference` | `[0]` | `BACnetObjectPropertyReference` | yes |
//!
//! Every member is context-tagged, so a property value carries a reference
//! as primitive context tags \[0\]/\[1\] (plus optional \[2\]) concatenated on
//! the wire; the `Setpoint_Reference` property nests those members in the
//! opening/closing tag 0 frame of `BACnetSetpointReference`, and leaves the
//! frame out entirely when it holds no reference (an absent optional member
//! has no encoding, Clause 20.2.16). Unlike
//! `BACnetDeviceObjectPropertyReference` there is NO device member in this
//! production — these references name objects in the local device only — so
//! a device-qualifying \[3\] element is rejected on decode rather than being
//! silently absorbed (the tranche-J `decode_dopr_body` codec accepts
//! \[3\]; this codec narrows it).

use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::error::Error;
use bytes::BytesMut;

use crate::primitives;
use crate::tags;

use super::decode_dopr_body;
use super::tagged::{decode_ctx_constructed, expect_end};

const WHAT: &str = "BACnetObjectPropertyReference";

/// Encode the bare `BACnetObjectPropertyReference` member sequence:
/// context-tagged \[0\]/\[1\] plus \[2\] when the reference is indexed.
pub fn encode_object_property_reference(buf: &mut BytesMut, r: &BACnetObjectPropertyReference) {
    primitives::encode_ctx_object_id(buf, 0, &r.object_identifier);
    primitives::encode_ctx_unsigned(buf, 1, r.property_identifier as u64);
    if let Some(index) = r.property_array_index {
        primitives::encode_ctx_unsigned(buf, 2, index as u64);
    }
}

/// Encode the `BACnetSetpointReference` form: the reference inside an
/// opening/closing context tag 0 frame (the production's
/// `setpoint-reference [0]` member).
pub fn encode_setpoint_reference(buf: &mut BytesMut, r: &BACnetObjectPropertyReference) {
    tags::encode_opening_tag(buf, 0);
    encode_object_property_reference(buf, r);
    tags::encode_closing_tag(buf, 0);
}

/// Decode a whole property-value payload as the bare
/// `BACnetObjectPropertyReference` member sequence.
///
/// Full consumption is required and the production is narrowed relative to
/// the shared DOPR body codec: a device-qualifying member `[3]` is not part
/// of `BACnetObjectPropertyReference` (the Loop/Pulse Converter references
/// are local-device only), so it is rejected — as is any other content
/// trailing the \[0\]/\[1\]/\[2\] members.
pub fn decode_object_property_reference(
    data: &[u8],
) -> Result<BACnetObjectPropertyReference, Error> {
    let (dopr, end) = decode_dopr_body(data, 0, WHAT)?;
    expect_end(data, end, end, WHAT)?;
    if dopr.device_identifier.is_some() {
        return Err(Error::decoding(
            0,
            format!("{WHAT}: [3] device-identifier is not part of this production"),
        ));
    }
    Ok(BACnetObjectPropertyReference {
        object_identifier: dopr.object_identifier,
        property_identifier: dopr.property_identifier,
        property_array_index: dopr.property_array_index,
    })
}

/// Decode a whole property-value payload as the `BACnetSetpointReference`
/// form: an opening/closing context tag 0 frame whose content is the bare
/// reference, decoded with [`decode_object_property_reference`]'s strictness.
///
/// The production's one member is optional, and an absent member has no
/// encoding (Clause 20.2.16), so an empty payload is the value without a
/// reference and yields `None`: Clause 12.17.16 then takes the setpoint from
/// the Loop's Setpoint property. A frame with nothing inside (`0x0E 0x0F`) is
/// the member present but holding no object or property, which this refuses
/// like any other incomplete reference.
pub fn decode_setpoint_reference(
    data: &[u8],
) -> Result<Option<BACnetObjectPropertyReference>, Error> {
    if data.is_empty() {
        return Ok(None);
    }
    let what = "BACnetSetpointReference";
    let (inner, after) = decode_ctx_constructed(data, 0, 0, what)?;
    expect_end(data, after, after, what)?;
    decode_object_property_reference(inner).map(Some)
}

#[cfg(test)]
mod tests;
