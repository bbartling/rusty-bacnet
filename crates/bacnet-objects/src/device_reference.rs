//! Read values and write decoding for the device-qualified reference
//! properties (#1182, #1234).
//!
//! A `BACnetDeviceObjectPropertyReference` or `BACnetDeviceObjectReference`
//! value is served as `PropertyValue::ApplicationData` holding the reference's
//! context-tagged members, encoded by the shared codecs in
//! `bacnet_encoding::constructed`: an array or list of them is one such value
//! per element. Averaging, Event Enrollment, Trend Log, Trend Log Multiple and
//! both Life Safety objects encode through these helpers, so each reference
//! type has one encoding whichever object serves it. Sharing the encoding
//! doesn't mean sharing the Device check: [`check_device_member`] lists the
//! setters that run it and the ones that don't yet.

use bacnet_encoding::constructed::{
    decode_device_object_property_reference, encode_device_object_property_reference,
    encode_device_object_reference,
};
use bacnet_encoding::tags;
use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, BACnetDeviceObjectReference};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::BytesMut;

use crate::common;

/// One `BACnetDeviceObjectPropertyReference` as a read serves it.
pub(crate) fn property_reference_value(
    reference: &BACnetDeviceObjectPropertyReference,
) -> PropertyValue {
    let mut encoded = BytesMut::new();
    encode_device_object_property_reference(&mut encoded, reference);
    PropertyValue::ApplicationData(encoded.to_vec())
}

/// One `BACnetDeviceObjectReference` as a read serves it.
pub(crate) fn object_reference_value(reference: &BACnetDeviceObjectReference) -> PropertyValue {
    let mut encoded = BytesMut::new();
    encode_device_object_reference(&mut encoded, reference);
    PropertyValue::ApplicationData(encoded.to_vec())
}

/// A BACnetLIST of `BACnetDeviceObjectReference`, one value per element.
pub(crate) fn object_reference_list(references: &[BACnetDeviceObjectReference]) -> PropertyValue {
    PropertyValue::List(references.iter().map(object_reference_value).collect())
}

/// Every `BACnetDeviceObjectPropertyReference` in a written value, in order.
///
/// The value is raw member bytes (the WriteProperty payload), or a list of
/// such chunks (the shape a read returns); each chunk holds whole references
/// back to back. A chunk whose next element can't begin a reference, because
/// it doesn't open with the object identifier's primitive context tag 0, or a
/// value of any other kind, is PROPERTY / INVALID_DATA_TYPE. One that begins
/// right but doesn't decode in full is PROPERTY / INVALID_DATA_ENCODING.
pub(crate) fn decode_property_references(
    value: &PropertyValue,
) -> Result<Vec<BACnetDeviceObjectPropertyReference>, Error> {
    let chunks: Vec<&[u8]> = match value {
        PropertyValue::ApplicationData(bytes) => vec![bytes],
        PropertyValue::List(items) => items
            .iter()
            .map(|item| match item {
                PropertyValue::ApplicationData(bytes) => Ok(bytes.as_slice()),
                _ => Err(common::invalid_data_type_error()),
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(common::invalid_data_type_error()),
    };
    let mut references = Vec::new();
    for bytes in chunks {
        let mut offset = 0;
        while offset < bytes.len() {
            match tags::decode_tag(bytes, offset) {
                Ok((tag, _)) if tag.is_context(0) => {}
                Ok(_) => return Err(common::invalid_data_type_error()),
                Err(_) => return Err(common::invalid_data_encoding_error()),
            }
            let (reference, end) = decode_device_object_property_reference(bytes, offset)
                .map_err(|_| common::invalid_data_encoding_error())?;
            references.push(reference);
            offset = end;
        }
    }
    Ok(references)
}

/// The one reference a written single-reference value holds. More than one,
/// or none, is PROPERTY / INVALID_DATA_ENCODING; see
/// [`decode_property_references`] for the other refusals.
pub(crate) fn decode_property_reference(
    value: &PropertyValue,
) -> Result<BACnetDeviceObjectPropertyReference, Error> {
    let mut references = decode_property_references(value)?;
    match references.pop() {
        Some(reference) if references.is_empty() => Ok(reference),
        _ => Err(common::invalid_data_encoding_error()),
    }
}

/// Refuse a Device member that isn't a Device object identifier with
/// PROPERTY / VALUE_OUT_OF_RANGE: the member names the device holding the
/// object, so any other object type can't be honoured.
///
/// The rule is bacnet-types' `device_identifier_is_device`, which the
/// reference types' methods and the Python bindings apply too. These setters
/// and write paths run this on each reference before storing any, so a
/// refused list leaves the property as it was: Averaging
/// Object_Property_Reference, the Log_DeviceObjectProperty of a Trend Log or
/// of a Trend Log Multiple, the Life Safety member lists (#1182), Access
/// Door Door_Members, Access Point Access_Doors and Access_Event_Credential,
/// Access Credential Assigned_Access_Rights, Staging Target_References,
/// Structured View Subordinate_List, the elevator family's Energy_Meter_Ref
/// and Channel List_Of_Object_Property_References (#1285), both references
/// in each Access Rights rule (#1316), and Access Zone Entry_Points and
/// Exit_Points (#1306).
///
/// Not all of them yet: Event Enrollment's setter, Schedule
/// List_Of_Object_Property_References, Global Group members and Command
/// action lists store a reference without this check (#1308).
pub(crate) fn check_device_member(device: Option<ObjectIdentifier>) -> Result<(), Error> {
    if bacnet_types::constructed::device_identifier_is_device(device) {
        Ok(())
    } else {
        Err(common::value_out_of_range_error())
    }
}

#[cfg(test)]
#[path = "device_reference_tests.rs"]
mod tests;
