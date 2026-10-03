//! The device identifier of a BACnetDeviceObjectReference (#1285).

use bacnet_types::constructed::BACnetDeviceObjectReference;
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
    if reference.device_identifier_is_device() {
        Ok(())
    } else {
        Err(super::value_out_of_range_error())
    }
}
