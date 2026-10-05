//! Log_DeviceObjectProperty on both trend objects (#1234): a Trend Log holds
//! one `BACnetDeviceObjectPropertyReference` (Clause 12.25.8), a Trend Log
//! Multiple a BACnetARRAY of them (Clause 12.30.11). Both serve the shared
//! Clause 21 encoding and take network writes through the checks here.

use bacnet_types::constructed::BACnetDeviceObjectPropertyReference;
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType};
use bacnet_types::error::Error;

use crate::common;
use crate::device_reference::{check_device_member, check_local_member};

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
/// Multiple's array: the shared unset form, Analog Input 4194303's
/// Present_Value, an empty element under Clause 12.30.11, so the poller logs
/// NO_PROPERTY_SPECIFIED for it. A Trend Log without a reference reads as the
/// same reference (#1417).
pub(super) fn empty_element() -> BACnetDeviceObjectPropertyReference {
    crate::device_reference::unset_reference(ObjectType::ANALOG_INPUT)
}

/// Check a reference a client writes with the shared
/// [`check_local_member`]: a Device member that isn't a Device identifier is
/// PROPERTY / VALUE_OUT_OF_RANGE, and any other Device member PROPERTY /
/// OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, since the poller reads only its own
/// database, which both clauses let a writable reference be held to. The
/// bundled server has already put one naming its own Device in local form.
/// An unset reference, its object or Device instance 4194303, names nothing
/// (Clause 12.30.11 for a Trend Log Multiple element), so a Device member
/// there is kept as written.
pub(super) fn check_written(reference: &BACnetDeviceObjectPropertyReference) -> Result<(), Error> {
    check_device_member(reference.device_identifier)?;
    if reference.is_unset() {
        return Ok(());
    }
    check_local_member(reference.device_identifier)
}
