//! One decoder for the value octets a property read carries (#1296): a
//! ReadProperty ACK, a ReadPropertyMultiple result, a COV notification value,
//! and the local `BACnetServer.read_property`, which encodes the served value
//! first so it comes back exactly as a network read would.
//!
//! The octets are walked one tagged element at a time:
//!
//! - When any element carries a context tag, the value is a constructed
//!   production (a list of BACnetDestination, a Group's read results, a
//!   timestamp CHOICE and so on). Nothing in the octets says where one list
//!   element ends and the next starts, so the whole value comes back as
//!   [`PropertyValue::ApplicationData`] holding the octets as received. Local
//!   reads and writes already carry such values that way, and writing one
//!   back sends the same octets.
//! - Otherwise each element decodes to its typed value. A whole read (no array
//!   index) of a property the standard types as a BACnetARRAY or BACnetLIST on
//!   that object type is a [`PropertyValue::List`] at every length, zero and
//!   one included, so its shape doesn't follow its length. Any other read is
//!   the bare value when it holds exactly one element, and a list in wire
//!   order when it holds none or several (a BACnetDateTime is a Date and then
//!   a Time, for example).

use bacnet_encoding::primitives::decode_application_value;
use bacnet_objects::traits::{standard_array_property, standard_list_property};
use bacnet_services::read_property::ReadPropertyACK;
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

/// Decode the value octets read from `property` of an object of
/// `object_type`, with the read's `array_index`, by the rules in the module
/// documentation. Malformed octets are an error; a caller that reports raw
/// octets instead keeps that fallback.
pub(crate) fn decode_read_value(
    object_type: ObjectType,
    property: PropertyIdentifier,
    array_index: Option<u32>,
    octets: &[u8],
) -> Result<PropertyValue, Error> {
    let mut elements = Vec::new();
    let mut constructed = false;
    let mut offset = 0;
    while offset < octets.len() {
        let (element, next) = decode_application_value(octets, offset)?;
        // Keep walking a constructed value to check its framing to the end.
        if matches!(element, PropertyValue::ApplicationData(_)) {
            constructed = true;
            elements.clear();
        } else if !constructed {
            elements.push(element);
        }
        offset = next;
    }
    if constructed {
        return Ok(PropertyValue::ApplicationData(octets.to_vec()));
    }
    let collection = array_index.is_none()
        && (standard_array_property(object_type, property)
            || standard_list_property(object_type, property));
    Ok(match <[PropertyValue; 1]>::try_from(elements) {
        Ok([element]) if !collection => element,
        Ok([element]) => PropertyValue::List(vec![element]),
        Err(elements) => PropertyValue::List(elements),
    })
}

/// Decode a ReadProperty ACK's value, shaped by the object, property and
/// array index the ACK names.
pub(crate) fn decode_read_ack(ack: &ReadPropertyACK) -> Result<PropertyValue, Error> {
    decode_read_value(
        ack.object_identifier.object_type(),
        ack.property_identifier,
        ack.property_array_index,
        &ack.property_value,
    )
}

#[cfg(test)]
#[path = "read_value_tests.rs"]
mod tests;
