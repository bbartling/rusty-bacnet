//! The device identifier of a device-qualified reference (#1285).

use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, BACnetDeviceObjectReference};
use bacnet_types::error::Error;

/// VALUE_OUT_OF_RANGE for a reference whose device identifier names anything
/// but a Device object (Clause 21); a reference with no device identifier, or
/// with a Device one, passes.
///
/// Every setter and write path that stores these references runs it on each
/// one before storing any, so a refused list leaves the property as it was:
/// Access Door Door_Members, Access Point Access_Doors and
/// Access_Event_Credential, Access Credential Assigned_Access_Rights, Staging
/// Target_References, Structured View Subordinate_List and the elevator
/// family's Energy_Meter_Ref.
pub(crate) fn check_device_reference(reference: &BACnetDeviceObjectReference) -> Result<(), Error> {
    device_member(reference.device_identifier_is_device())
}

/// The same rule for a BACnetDeviceObjectPropertyReference, whose optional
/// device member holds the same kind of identifier. Channel
/// List_Of_Object_Property_References runs it on each member, from the
/// setter and from network writes alike.
pub(crate) fn check_device_property_reference(
    reference: &BACnetDeviceObjectPropertyReference,
) -> Result<(), Error> {
    device_member(reference.device_identifier_is_device())
}

fn device_member(is_device: bool) -> Result<(), Error> {
    if is_device {
        Ok(())
    } else {
        Err(super::value_out_of_range_error())
    }
}
