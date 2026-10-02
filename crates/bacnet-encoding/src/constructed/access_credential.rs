//! Clause 21 codecs for the elements of two Access Credential arrays
//! (Clause 12.35): Assigned_Access_Rights (`BACnetAssignedAccessRights`) and
//! Authentication_Factors (`BACnetCredentialAuthenticationFactor`, which
//! embeds a `BACnetAuthenticationFactor`).
//!
//! Each element is a bare SEQUENCE; a whole array concatenates them with no
//! wrapper, so each decoder reads one element at `offset` and returns the
//! offset just past it. A caller holding exactly one element must check that
//! offset reaches the end of its data.
//!
//! The decoders check structure only. Enumerated members up to 32 bits are
//! kept as received, reserved and vendor values included, for the object to
//! judge; a member wider than 32 bits is malformed.

use bacnet_types::constructed::{
    BACnetAssignedAccessRights, BACnetAuthenticationFactor, BACnetCredentialAuthenticationFactor,
};
use bacnet_types::enums::{AccessAuthenticationFactorDisable, AuthenticationFactorType};
use bacnet_types::error::Error;
use bytes::BytesMut;

use super::cov_subscription::decode_ctx_boolean;
use super::{
    decode_ctx_unsigned, decode_device_object_reference, encode_device_object_reference,
    expect_closing, expect_opening,
};
use crate::{primitives, tags};

const RIGHTS: &str = "BACnetAssignedAccessRights";
const FACTOR: &str = "BACnetAuthenticationFactor";
const CREDENTIAL_FACTOR: &str = "BACnetCredentialAuthenticationFactor";

/// Encode one `BACnetAssignedAccessRights` SEQUENCE: the reference inside
/// opening and closing tag 0, then the enable flag as context `[1]`.
pub fn encode_assigned_access_rights(buf: &mut BytesMut, value: &BACnetAssignedAccessRights) {
    tags::encode_opening_tag(buf, 0);
    encode_device_object_reference(buf, &value.assigned_access_rights);
    tags::encode_closing_tag(buf, 0);
    primitives::encode_ctx_boolean(buf, 1, value.enable);
}

/// Decode one `BACnetAssignedAccessRights` SEQUENCE at `offset`.
///
/// A missing frame or member, a frame holding anything but one
/// device-object reference, or a BOOLEAN whose contents aren't 0 or 1 fails
/// with [`Error::Decoding`] or [`Error::BufferTooShort`].
pub fn decode_assigned_access_rights(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetAssignedAccessRights, usize), Error> {
    let pos = expect_opening(data, offset, 0, RIGHTS)?;
    let (assigned_access_rights, pos) = decode_device_object_reference(data, pos)?;
    let pos = expect_closing(data, pos, 0, RIGHTS)?;
    let (enable, end) = decode_ctx_boolean(data, pos, 1, RIGHTS)?;
    Ok((
        BACnetAssignedAccessRights {
            assigned_access_rights,
            enable,
        },
        end,
    ))
}

/// Encode one `BACnetAuthenticationFactor` SEQUENCE: format type `[0]`,
/// format class `[1]` and value `[2]`, all primitive context tags.
pub fn encode_authentication_factor(buf: &mut BytesMut, value: &BACnetAuthenticationFactor) {
    primitives::encode_ctx_enumerated(buf, 0, value.format_type.to_raw());
    primitives::encode_ctx_unsigned(buf, 1, u64::from(value.format_class));
    primitives::encode_ctx_octet_string(buf, 2, &value.value);
}

/// Decode one `BACnetAuthenticationFactor` SEQUENCE at `offset`.
///
/// The three members must appear in order. A missing or out-of-order member,
/// a truncated one, or a format type or class wider than 32 bits fails with
/// [`Error::Decoding`] or [`Error::BufferTooShort`]; an empty value is
/// accepted.
pub fn decode_authentication_factor(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetAuthenticationFactor, usize), Error> {
    let (format_type, pos) = decode_ctx_u32(data, offset, 0, FACTOR)?;
    let (format_class, pos) = decode_ctx_u32(data, pos, 1, FACTOR)?;
    let (value, end) = decode_ctx_octets(data, pos, 2, FACTOR)?;
    Ok((
        BACnetAuthenticationFactor {
            format_type: AuthenticationFactorType::from_raw(format_type),
            format_class,
            value,
        },
        end,
    ))
}

/// Encode one `BACnetCredentialAuthenticationFactor` SEQUENCE: the disable
/// value as context `[0]`, then the factor inside opening and closing tag 1.
pub fn encode_credential_authentication_factor(
    buf: &mut BytesMut,
    value: &BACnetCredentialAuthenticationFactor,
) {
    primitives::encode_ctx_enumerated(buf, 0, value.disable.to_raw());
    tags::encode_opening_tag(buf, 1);
    encode_authentication_factor(buf, &value.authentication_factor);
    tags::encode_closing_tag(buf, 1);
}

/// Decode one `BACnetCredentialAuthenticationFactor` SEQUENCE at `offset`.
///
/// Fails as [`decode_authentication_factor`] does, and also when the disable
/// member is missing or wider than 32 bits or the factor's frame is missing
/// or holds anything after the factor.
pub fn decode_credential_authentication_factor(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetCredentialAuthenticationFactor, usize), Error> {
    let (disable, pos) = decode_ctx_u32(data, offset, 0, CREDENTIAL_FACTOR)?;
    let pos = expect_opening(data, pos, 1, CREDENTIAL_FACTOR)?;
    let (authentication_factor, pos) = decode_authentication_factor(data, pos)?;
    let end = expect_closing(data, pos, 1, CREDENTIAL_FACTOR)?;
    Ok((
        BACnetCredentialAuthenticationFactor {
            disable: AccessAuthenticationFactorDisable::from_raw(disable),
            authentication_factor,
        },
        end,
    ))
}

/// A primitive context tag `tag` holding an Unsigned or ENUMERATED of at
/// most 32 bits.
fn decode_ctx_u32(data: &[u8], offset: usize, tag: u8, what: &str) -> Result<(u32, usize), Error> {
    let (value, end) = decode_ctx_unsigned(data, offset, tag, what)?;
    let value = u32::try_from(value)
        .map_err(|_| Error::decoding(offset, format!("{what}: [{tag}] exceeds 32 bits")))?;
    Ok((value, end))
}

/// A primitive context tag `tag` holding an OCTET STRING.
fn decode_ctx_octets(
    data: &[u8],
    offset: usize,
    tag: u8,
    what: &str,
) -> Result<(Vec<u8>, usize), Error> {
    let (t, pos) = tags::decode_tag(data, offset)?;
    if !t.is_context(tag) {
        return Err(Error::decoding(
            offset,
            format!("{what}: expected context tag [{tag}] OCTET STRING"),
        ));
    }
    let end = pos
        .checked_add(t.length as usize)
        .ok_or_else(|| Error::decoding(pos, format!("{what}: length overflow")))?;
    if end > data.len() {
        return Err(Error::buffer_too_short(end, data.len()));
    }
    Ok((data[pos..end].to_vec(), end))
}
