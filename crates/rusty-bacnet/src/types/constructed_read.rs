//! Typed read results for the constructed collection properties the binding
//! also takes as typed values (#1310).
//!
//! Nothing in a list of constructed elements marks where one element ends,
//! so the generic decoder in `read_value` can't split it. For the properties
//! [`element`] names, the element's datatype is known, so the value is split
//! with that datatype's codec from `bacnet_encoding::constructed` (or, for a
//! Group's Present_Value, the ReadPropertyMultiple ACK decoder). Each element
//! keeps its own octets, so the value encodes back to exactly what was read,
//! and its Python form is built from those octets when `.value` is asked for.
//! A value that doesn't decode as the expected elements, to the last octet,
//! is left to the generic decoder.

use bacnet_encoding::constructed::{
    decode_action_list, decode_authentication_factor_format, decode_destination,
    decode_device_object_reference, decode_port_permission, decode_read_access_specification,
    decode_stage_limit_value,
};
use bacnet_encoding::primitives::encode_property_value;
use bacnet_encoding::tags;
use bacnet_services::rpm::{ReadAccessResult, ReadPropertyMultipleACK};
use bacnet_types::constructed::{
    BACnetActionCommand, BACnetActionList, BACnetAuthenticationFactorFormat, BACnetDestination,
    BACnetDeviceObjectReference, BACnetPortPermission, BACnetStageLimitValue,
    ReadAccessSpecification,
};
use bacnet_types::enums::{ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;
use bytes::BytesMut;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use super::audit_projection::recipient_to_py;
use super::read_value::decode_read_value;
use super::rpm_wpm::read_access_result_to_py;
use super::timestamp::time_value;
use super::{PyObjectIdentifier, PyPropertyIdentifier, PyPropertyValue};

/// The constructed production a typed read splits a value into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Element {
    /// A Recipient_List destination, as a `Destination` mapping.
    Destination,
    /// A Port_Filter element, as a `(port_id, enabled)` pair.
    PortPermission,
    /// A Group member, in the `read_property_multiple` spec shape.
    ReadAccessSpecification,
    /// A Group's Present_Value result, in the `read_property_multiple`
    /// result shape.
    ReadAccessResult,
    /// A Command's action list, as a list of `ActionCommand` mappings.
    ActionList,
    /// An object reference: an `ObjectIdentifier`, or a `(device, object)`
    /// pair when it names a device.
    DeviceObjectReference,
    /// A Supported_Formats element: the format type, or a `(format_type,
    /// vendor_id, vendor_format)` triple when it carries vendor members.
    AuthenticationFactorFormat,
    /// A Stages element, as a `(limit, values, deadband)` triple.
    StageLimitValue,
}

/// The element production of `property` on `object_type`, for the
/// collections the binding reads as typed values.
pub(crate) fn element(object_type: ObjectType, property: PropertyIdentifier) -> Option<Element> {
    type O = ObjectType;
    type P = PropertyIdentifier;
    Some(match (object_type, property) {
        (O::NOTIFICATION_CLASS | O::NOTIFICATION_FORWARDER, P::RECIPIENT_LIST) => {
            Element::Destination
        }
        (O::NOTIFICATION_FORWARDER, P::PORT_FILTER) => Element::PortPermission,
        (O::GROUP, P::LIST_OF_GROUP_MEMBERS) => Element::ReadAccessSpecification,
        (O::GROUP, P::PRESENT_VALUE) => Element::ReadAccessResult,
        (O::COMMAND, P::ACTION) => Element::ActionList,
        (O::ACCESS_DOOR, P::DOOR_MEMBERS)
        | (O::ACCESS_POINT, P::ACCESS_DOORS)
        | (O::STAGING, P::TARGET_REFERENCES) => Element::DeviceObjectReference,
        (O::CREDENTIAL_DATA_INPUT, P::SUPPORTED_FORMATS) => Element::AuthenticationFactorFormat,
        (O::STAGING, P::STAGES) => Element::StageLimitValue,
        _ => return None,
    })
}

/// The typed form of a read of `property` on `object_type`, or `None` when
/// the property has no element production here or `octets` don't decode as
/// its elements; the generic decoder then takes the value.
///
/// A whole read is a list of the elements and an indexed read one element.
/// An empty value and index 0 (an array's size) are left to the generic
/// decoder, which already gives them their shape.
pub(crate) fn decode(
    object_type: ObjectType,
    property: PropertyIdentifier,
    array_index: Option<u32>,
    octets: &[u8],
) -> Option<PyPropertyValue> {
    let element = element(object_type, property)?;
    let ends = element.split(octets)?;
    match array_index {
        None if !ends.is_empty() => {
            let mut start = 0;
            let elements = ends
                .into_iter()
                .map(|end| {
                    let element = PropertyValue::ApplicationData(octets[start..end].to_vec());
                    start = end;
                    element
                })
                .collect();
            Some(PyPropertyValue::constructed(
                PropertyValue::List(elements),
                element,
            ))
        }
        Some(index) if index != 0 && ends.len() == 1 => Some(PyPropertyValue::constructed(
            PropertyValue::ApplicationData(octets.to_vec()),
            element,
        )),
        _ => None,
    }
}

/// One element, decoded.
enum Decoded {
    Destination(BACnetDestination),
    PortPermission(BACnetPortPermission),
    ReadAccessSpecification(ReadAccessSpecification),
    ReadAccessResult(ReadAccessResult),
    ActionList(BACnetActionList),
    DeviceObjectReference(BACnetDeviceObjectReference),
    AuthenticationFactorFormat(BACnetAuthenticationFactorFormat),
    StageLimitValue(BACnetStageLimitValue),
}

impl Element {
    /// The `PropertyValue.tag` of one element.
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Destination => "destination",
            Self::PortPermission => "port_permission",
            Self::ReadAccessSpecification => "read_access_specification",
            Self::ReadAccessResult => "read_access_result",
            Self::ActionList => "action_list",
            Self::DeviceObjectReference => "device_object_reference",
            Self::AuthenticationFactorFormat => "authentication_factor_format",
            Self::StageLimitValue => "stage_limit_value",
        }
    }

    /// The Python form of one element's octets. They decoded when the read
    /// was split, so they decode again here; if they somehow didn't, the
    /// octets come back as `bytes` rather than raising.
    pub(crate) fn to_py(self, py: Python<'_>, octets: &[u8]) -> PyResult<Py<PyAny>> {
        match self.decode_at(octets, 0) {
            Ok((decoded, _)) => decoded.into_python(py),
            Err(_) => Ok(PyBytes::new(py, octets).into_any().unbind()),
        }
    }

    /// Where each element of `octets` ends, or `None` when one doesn't
    /// decode.
    fn split(self, octets: &[u8]) -> Option<Vec<usize>> {
        let mut ends = Vec::new();
        let mut offset = 0;
        while offset < octets.len() {
            let (_, end) = self.decode_at(octets, offset).ok()?;
            if end <= offset {
                return None;
            }
            ends.push(end);
            offset = end;
        }
        Some(ends)
    }

    /// Decode the element at `offset`, returning it and the offset past it.
    fn decode_at(self, octets: &[u8], offset: usize) -> Result<(Decoded, usize), Error> {
        Ok(match self {
            Self::Destination => {
                let (value, end) = decode_destination(octets, offset)?;
                (Decoded::Destination(value), end)
            }
            Self::PortPermission => {
                let (value, end) = decode_port_permission(octets, offset)?;
                (Decoded::PortPermission(value), end)
            }
            Self::ReadAccessSpecification => {
                let (value, end) = decode_read_access_specification(octets, offset)?;
                (Decoded::ReadAccessSpecification(value), end)
            }
            Self::ReadAccessResult => {
                let (value, end) = read_access_result(octets, offset)?;
                (Decoded::ReadAccessResult(value), end)
            }
            Self::ActionList => {
                let (value, end) = decode_action_list(octets, offset)?;
                (Decoded::ActionList(value), end)
            }
            Self::DeviceObjectReference => {
                let (value, end) = decode_device_object_reference(octets, offset)?;
                (Decoded::DeviceObjectReference(value), end)
            }
            Self::AuthenticationFactorFormat => {
                let (value, end) = decode_authentication_factor_format(octets, offset)?;
                (Decoded::AuthenticationFactorFormat(value), end)
            }
            Self::StageLimitValue => {
                let (value, end) = decode_stage_limit_value(octets, offset)?;
                (Decoded::StageLimitValue(value), end)
            }
        })
    }
}

/// Decode one Group Present_Value element at `offset`: an object identifier
/// in context tag 0, then its results inside an opening and closing tag 1.
/// The element is one result of a ReadPropertyMultiple ACK, so that ACK's
/// decoder checks it.
fn read_access_result(octets: &[u8], offset: usize) -> Result<(ReadAccessResult, usize), Error> {
    let (tag, contents) = tags::decode_tag(octets, offset)?;
    if !tag.is_context(0) || tag.is_opening || tag.is_closing {
        return Err(Error::decoding(
            offset,
            "expected the object identifier [0]",
        ));
    }
    let after = contents
        .checked_add(tag.length as usize)
        .filter(|&after| after <= octets.len())
        .ok_or_else(|| Error::decoding(contents, "object identifier cut short"))?;
    let (tag, contents) = tags::decode_tag(octets, after)?;
    if !tag.is_opening_tag(1) {
        return Err(Error::decoding(after, "expected the results [1]"));
    }
    let (_, end) = tags::extract_context_value(octets, contents, 1)?;
    let ack = ReadPropertyMultipleACK::decode(&octets[offset..end])?;
    let [result] = <[ReadAccessResult; 1]>::try_from(ack.list_of_read_access_results)
        .map_err(|_| Error::decoding(offset, "expected one result"))?;
    Ok((result, end))
}

impl Decoded {
    fn into_python(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        Ok(match self {
            Self::Destination(destination) => {
                destination_to_py(py, &destination)?.into_any().unbind()
            }
            Self::PortPermission(permission) => (permission.port_id, permission.enabled)
                .into_pyobject(py)?
                .into_any()
                .unbind(),
            Self::ReadAccessSpecification(specification) => specification_to_py(py, specification)?,
            Self::ReadAccessResult(result) => {
                read_access_result_to_py(py, result)?.into_any().unbind()
            }
            Self::ActionList(list) => {
                let commands = PyList::empty(py);
                for command in &list.commands {
                    commands.append(action_command_to_py(py, command)?)?;
                }
                commands.into_any().unbind()
            }
            Self::DeviceObjectReference(reference) => {
                let object = PyObjectIdentifier::from_rust(reference.object_identifier);
                match reference.device_identifier {
                    None => object.into_pyobject(py)?.into_any().unbind(),
                    Some(device) => (PyObjectIdentifier::from_rust(device), object)
                        .into_pyobject(py)?
                        .into_any()
                        .unbind(),
                }
            }
            Self::AuthenticationFactorFormat(format) => {
                let format_type = format.format_type.to_raw();
                match (format.vendor_id, format.vendor_format) {
                    (None, None) => format_type.into_pyobject(py)?.into_any().unbind(),
                    (vendor_id, vendor_format) => (format_type, vendor_id, vendor_format)
                        .into_pyobject(py)?
                        .into_any()
                        .unbind(),
                }
            }
            Self::StageLimitValue(stage) => (
                f64::from(stage.limit),
                stage.values,
                f64::from(stage.deadband),
            )
                .into_pyobject(py)?
                .into_any()
                .unbind(),
        })
    }
}

/// One destination, in the `Destination` mapping `add_notification_forwarder`
/// takes, with every key present.
fn destination_to_py<'py>(
    py: Python<'py>,
    destination: &BACnetDestination,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("recipient", recipient_to_py(py, &destination.recipient)?)?;
    dict.set_item("process_identifier", destination.process_identifier)?;
    dict.set_item("valid_days", destination.valid_days.bits())?;
    dict.set_item("from_time", time_value(&destination.from_time))?;
    dict.set_item("to_time", time_value(&destination.to_time))?;
    dict.set_item(
        "issue_confirmed_notifications",
        destination.issue_confirmed_notifications,
    )?;
    dict.set_item("transitions", destination.transitions.bits())?;
    Ok(dict)
}

/// One member, as `(object, [(property, array_index), ...])`.
fn specification_to_py(
    py: Python<'_>,
    specification: ReadAccessSpecification,
) -> PyResult<Py<PyAny>> {
    let references: Vec<_> = specification
        .list_of_property_references
        .into_iter()
        .map(|reference| {
            (
                PyPropertyIdentifier {
                    inner: reference.property_identifier,
                },
                reference.property_array_index,
            )
        })
        .collect();
    Ok((
        PyObjectIdentifier::from_rust(specification.object_identifier),
        references,
    )
        .into_pyobject(py)?
        .into_any()
        .unbind())
}

/// One command, in the `ActionCommand` mapping `add_command` takes, with
/// every key present. Its value reads as a read of the property it writes
/// would, so a typed value stays typed.
fn action_command_to_py<'py>(
    py: Python<'py>,
    command: &BACnetActionCommand,
) -> PyResult<Bound<'py, PyDict>> {
    let mut encoded = BytesMut::new();
    let value = encode_property_value(&mut encoded, &command.property_value)
        .and_then(|()| {
            decode_read_value(
                command.object_identifier.object_type(),
                command.property_identifier,
                command.property_array_index,
                &encoded,
            )
        })
        .unwrap_or_else(|_| PyPropertyValue::from_rust(command.property_value.clone()));
    let dict = PyDict::new(py);
    dict.set_item(
        "device_identifier",
        command.device_identifier.map(PyObjectIdentifier::from_rust),
    )?;
    dict.set_item(
        "object_identifier",
        PyObjectIdentifier::from_rust(command.object_identifier),
    )?;
    dict.set_item(
        "property_identifier",
        PyPropertyIdentifier {
            inner: command.property_identifier,
        },
    )?;
    dict.set_item("property_array_index", command.property_array_index)?;
    dict.set_item("property_value", value)?;
    dict.set_item("priority", command.priority)?;
    dict.set_item("post_delay", command.post_delay)?;
    dict.set_item("quit_on_failure", command.quit_on_failure)?;
    dict.set_item("write_successful", command.write_successful)?;
    Ok(dict)
}

#[cfg(test)]
#[path = "constructed_read_tests.rs"]
mod tests;
