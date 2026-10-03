//! Log_DeviceObjectProperty on both trend objects (#1234): a Trend Log holds
//! one `BACnetDeviceObjectPropertyReference` (Clause 12.25.8), a Trend Log
//! Multiple a BACnetARRAY of them (Clause 12.30.11). Both serve the shared
//! Clause 21 encoding and take network writes through the checks here.

use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;

use crate::common;
use crate::device_reference::check_device_member;

/// The most references a Trend Log Multiple holds. Each poll reads every
/// one and each record carries a value per reference, so the array is
/// bounded locally; a longer one is RESOURCES / NO_SPACE_TO_WRITE_PROPERTY.
pub const MAX_LOG_DEVICE_OBJECT_PROPERTIES: usize = 64;

/// RESOURCES / NO_SPACE_TO_WRITE_PROPERTY, for a Trend Log Multiple array
/// past [`MAX_LOG_DEVICE_OBJECT_PROPERTIES`].
pub(super) fn no_space_error() -> Error {
    common::protocol_error(ErrorClass::RESOURCES, ErrorCode::NO_SPACE_TO_WRITE_PROPERTY)
}

/// The element a write of index 0 appends when it lengthens a Trend Log
/// Multiple's array: Analog Input 4194303's Present_Value, an empty element
/// under Clause 12.30.11, so the poller logs NO_PROPERTY_SPECIFIED for it.
pub(super) fn empty_element() -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference::new_local(
        ObjectIdentifier::new(
            ObjectType::ANALOG_INPUT,
            ObjectIdentifier::WILDCARD_INSTANCE,
        )
        .expect("the wildcard instance is a valid identifier"),
        PropertyIdentifier::PRESENT_VALUE.to_raw(),
    )
}

/// Check a reference a client writes.
///
/// A Device member that isn't a Device identifier is PROPERTY /
/// VALUE_OUT_OF_RANGE. Any other Device member is PROPERTY /
/// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED: the poller reads only its own
/// database, which both clauses let a writable reference be held to, and the
/// bundled server has already put one naming its own Device in local form.
/// With `empty_elements` (a Trend Log Multiple element), an object or Device
/// instance of 4194303 marks the element empty (Clause 12.30.11) and is kept
/// as written.
pub(super) fn check_written(
    reference: &BACnetDeviceObjectPropertyReference,
    empty_elements: bool,
) -> Result<(), Error> {
    check_device_member(reference.device_identifier)?;
    let Some(device) = reference.device_identifier else {
        return Ok(());
    };
    let wildcard =
        |oid: ObjectIdentifier| oid.instance_number() == ObjectIdentifier::WILDCARD_INSTANCE;
    if empty_elements && (wildcard(reference.object_identifier) || wildcard(device)) {
        return Ok(());
    }
    Err(common::protocol_error(
        ErrorClass::PROPERTY,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    ))
}
