//! Who-Am-I and You-Are services per ASHRAE 135-2020 Clause 16.11.
//!
//! Both requests use only application tags, as in the Who-Am-I-Request and You-Are-Request
//! productions of Clause 21.3.3.

use bacnet_encoding::primitives;
use bacnet_encoding::tags::{self, TagClass};
use bacnet_types::enums::ObjectType;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Read the content of the application tag `number` at `offset`; returns it with the offset
/// past the element.
fn app_content<'a>(
    data: &'a [u8],
    offset: usize,
    number: u8,
    context: &str,
    field: &str,
) -> Result<(&'a [u8], usize), Error> {
    if offset >= data.len() {
        return Err(Error::decoding(
            offset,
            format!("{context} truncated before {field}"),
        ));
    }
    let (tag, pos) = tags::decode_tag(data, offset)?;
    if tag.class != TagClass::Application || tag.number != number {
        return Err(Error::decoding(
            offset,
            format!("{context} expected application tag {number} for {field}"),
        ));
    }
    let end = pos
        .checked_add(tag.length as usize)
        .ok_or_else(|| Error::decoding(pos, format!("{context} length overflow")))?;
    if end > data.len() {
        return Err(Error::decoding(
            pos,
            format!("{context} truncated at {field}"),
        ));
    }
    Ok((&data[pos..end], end))
}

/// Decode the vendor ID, model name and serial number that start both requests.
fn decode_identity(data: &[u8], context: &str) -> Result<(u16, String, String, usize), Error> {
    let (content, offset) = app_content(data, 0, tags::app_tag::UNSIGNED, context, "vendor-id")?;
    let vendor_id = u16::try_from(primitives::decode_unsigned(content)?)
        .map_err(|_| Error::decoding(0, format!("{context} vendor-id exceeds 65535")))?;
    let (content, offset) = app_content(
        data,
        offset,
        tags::app_tag::CHARACTER_STRING,
        context,
        "model-name",
    )?;
    let model_name = primitives::decode_character_string(content)?;
    let (content, offset) = app_content(
        data,
        offset,
        tags::app_tag::CHARACTER_STRING,
        context,
        "serial-number",
    )?;
    let serial_number = primitives::decode_character_string(content)?;
    Ok((vendor_id, model_name, serial_number, offset))
}

fn encode_identity(
    buf: &mut BytesMut,
    vendor_id: u16,
    model_name: &str,
    serial_number: &str,
) -> Result<(), Error> {
    primitives::encode_app_unsigned(buf, u64::from(vendor_id));
    primitives::encode_app_character_string(buf, model_name)?;
    primitives::encode_app_character_string(buf, serial_number)
}

// ---------------------------------------------------------------------------
// WhoAmIRequest
// ---------------------------------------------------------------------------

/// Who-Am-I-Request service parameters (Clause 16.11.1, Table 16-13).
///
/// ```text
/// Who-Am-I-Request ::= SEQUENCE {
///     vendor-id     Unsigned16,
///     model-name    CharacterString,
///     serial-number CharacterString
/// }
/// ```
///
/// All three fields are application-tagged. Vendor 260, model "M" and serial "S" encode as
/// `22 01 04 72 00 4D 72 00 53`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoAmIRequest {
    /// Vendor identifier of the requesting device; equals its Vendor_Identifier property.
    pub vendor_id: u16,
    /// Model name of the requesting device; equals its Model_Name property.
    pub model_name: String,
    /// Serial number of the requesting device; equals its Serial_Number property.
    pub serial_number: String,
}

impl WhoAmIRequest {
    /// Encode the request parameters into `buf`; fails, leaving `buf` untouched, if a character
    /// string cannot be encoded.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let mut scratch = BytesMut::new();
        encode_identity(
            &mut scratch,
            self.vendor_id,
            &self.model_name,
            &self.serial_number,
        )?;
        buf.extend_from_slice(&scratch);
        Ok(())
    }

    /// Decode the request from service-request octets.
    ///
    /// Fails on missing, mistagged or truncated fields and on trailing data.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let (vendor_id, model_name, serial_number, offset) = decode_identity(data, "WhoAmI")?;
        if offset != data.len() {
            return Err(Error::decoding(offset, "WhoAmI has trailing data"));
        }
        Ok(Self {
            vendor_id,
            model_name,
            serial_number,
        })
    }
}

// ---------------------------------------------------------------------------
// YouAreRequest
// ---------------------------------------------------------------------------

/// You-Are-Request service parameters (Clause 16.11.3, Table 16-14).
///
/// ```text
/// You-Are-Request ::= SEQUENCE {
///     vendor-id          Unsigned16,
///     model-name         CharacterString,
///     serial-number      CharacterString,
///     device-identifier  BACnetObjectIdentifier OPTIONAL,
///     device-mac-address OctetString OPTIONAL
/// }
/// ```
///
/// Every field is application-tagged. At least one of `device_identifier` and
/// `device_mac_address` must be present; both [`encode`](Self::encode) and
/// [`decode`](Self::decode) reject a request with neither. The identifier, when present,
/// must name a Device object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YouAreRequest {
    /// Vendor identifier (Unsigned16) of the device that should act on the request.
    pub vendor_id: u16,
    /// Model name the target device reports in its Device object.
    pub model_name: String,
    /// Serial number the target device reports in its Device object.
    pub serial_number: String,
    /// Device object identifier to assign to the target device; `None` leaves it unchanged.
    pub device_identifier: Option<ObjectIdentifier>,
    /// MAC address to configure on the target device; `None` leaves it unchanged.
    pub device_mac_address: Option<Vec<u8>>,
}

impl YouAreRequest {
    /// Encode the request parameters into `buf`.
    ///
    /// Fails, leaving `buf` untouched, if neither optional field is present, the identifier
    /// is not a Device object, or a character string cannot be encoded.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        if self.device_identifier.is_none() && self.device_mac_address.is_none() {
            return Err(Error::Encoding(
                "YouAre needs a device identifier, a device MAC address, or both".into(),
            ));
        }
        if let Some(oid) = &self.device_identifier {
            if oid.object_type() != ObjectType::DEVICE {
                return Err(Error::Encoding(
                    "YouAre device identifier must name a Device object".into(),
                ));
            }
        }
        // Encode into a scratch buffer so a string error leaves `buf` unchanged.
        let mut scratch = BytesMut::new();
        encode_identity(
            &mut scratch,
            self.vendor_id,
            &self.model_name,
            &self.serial_number,
        )?;
        if let Some(oid) = &self.device_identifier {
            primitives::encode_app_object_id(&mut scratch, oid);
        }
        if let Some(mac) = &self.device_mac_address {
            primitives::encode_app_octet_string(&mut scratch, mac);
        }
        buf.extend_from_slice(&scratch);
        Ok(())
    }

    /// Decode the request from service-request octets.
    ///
    /// Fails on missing, mistagged or truncated fields, on a request carrying neither optional
    /// field, and on trailing data.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let (vendor_id, model_name, serial_number, mut offset) = decode_identity(data, "YouAre")?;

        let mut device_identifier = None;
        if offset < data.len() && is_app_tag(data, offset, tags::app_tag::OBJECT_IDENTIFIER)? {
            let (content, end) = app_content(
                data,
                offset,
                tags::app_tag::OBJECT_IDENTIFIER,
                "YouAre",
                "device-identifier",
            )?;
            let oid = ObjectIdentifier::decode(content)?;
            if oid.object_type() != ObjectType::DEVICE {
                return Err(Error::decoding(
                    offset,
                    "YouAre device identifier must name a Device object",
                ));
            }
            device_identifier = Some(oid);
            offset = end;
        }

        let mut device_mac_address = None;
        if offset < data.len() && is_app_tag(data, offset, tags::app_tag::OCTET_STRING)? {
            let (content, end) = app_content(
                data,
                offset,
                tags::app_tag::OCTET_STRING,
                "YouAre",
                "device-mac-address",
            )?;
            device_mac_address = Some(content.to_vec());
            offset = end;
        }

        if offset != data.len() {
            return Err(Error::decoding(
                offset,
                "YouAre has trailing or unexpected data",
            ));
        }
        if device_identifier.is_none() && device_mac_address.is_none() {
            return Err(Error::decoding(
                offset,
                "YouAre needs a device identifier, a device MAC address, or both",
            ));
        }

        Ok(Self {
            vendor_id,
            model_name,
            serial_number,
            device_identifier,
            device_mac_address,
        })
    }
}

/// True if the tag at `offset` is the application tag `number`.
fn is_app_tag(data: &[u8], offset: usize, number: u8) -> Result<bool, Error> {
    let (tag, _) = tags::decode_tag(data, offset)?;
    Ok(tag.class == TagClass::Application && tag.number == number)
}

#[cfg(test)]
#[path = "who_am_i_tests.rs"]
mod tests;
