//! Recipient_List writes and the cap on how many destinations the list holds
//! (#1098).

use bacnet_encoding::constructed::decode_destination;
use bacnet_types::constructed::BACnetDestination;
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use super::destination_from_flat_fields;
use crate::common;

/// The most destinations a Notification Class Recipient_List holds (#1098).
///
/// A site usually routes a class to a few front ends, operator workstations
/// or gateways, and the AE-CRL-B building block (Annex K.2.25) asks for room
/// for at least 8, so 32 leaves ample headroom. The bound also keeps the list
/// small on the wire. A destination naming a device encodes in at most 27
/// octets, and one naming an address with a MAC of up to 6 octets in at most
/// 35, so a full list of either kind takes at most 1,120 octets and a
/// ReadProperty of it fits B/IP's 1476-octet APDU unsegmented. Each event
/// transition the class routes fans out to at most this many notifications.
///
/// A write that would leave more destinations fails with RESOURCES /
/// NO_SPACE_TO_WRITE_PROPERTY, naming the first destination past the cap;
/// AddListElement reports that as NO_SPACE_TO_ADD_LIST_ELEMENT at the request
/// element that brought it (Clause 15.1.1.3). `add_destination` refuses the
/// same way, without the element.
pub const MAX_RECIPIENT_LIST_DESTINATIONS: usize = 32;

/// The refusal of a destination past [`MAX_RECIPIENT_LIST_DESTINATIONS`].
pub(super) fn no_space_error() -> Error {
    common::protocol_error(ErrorClass::RESOURCES, ErrorCode::NO_SPACE_TO_WRITE_PROPERTY)
}

/// The refusal of a written list's destination at `index` (from 0), the first
/// past the cap, named so ChangeList-Error can report it (#1048).
fn past_the_cap(index: usize) -> Error {
    common::at_list_element(no_space_error(), index)
}

/// Decode a whole-list Recipient_List write. Destinations are checked in
/// order, so the first one that fails to decode, or the first past the cap,
/// decides the error; a destination past the cap is refused before it is
/// decoded, as Calendar's Date_List does.
///
/// The framed wire form (`ApplicationData`, a BACnetLIST of BACnetDestination
/// per Clause 12.21) is strict: one malformed destination refuses the whole
/// write. The legacy flat application-tagged form (pre-#152 layout) is still
/// accepted so older internal clients keep working.
pub(super) fn decode_write(value: PropertyValue) -> Result<Vec<BACnetDestination>, Error> {
    let mut list = Vec::new();
    match value {
        PropertyValue::ApplicationData(bytes) => {
            let mut offset = 0;
            while offset < bytes.len() {
                if list.len() == MAX_RECIPIENT_LIST_DESTINATIONS {
                    return Err(past_the_cap(list.len()));
                }
                let (destination, next) = decode_destination(&bytes, offset)
                    .map_err(|_| common::invalid_data_type_error())?;
                list.push(destination);
                offset = next;
            }
        }
        PropertyValue::List(entries) => {
            for entry in entries {
                if list.len() == MAX_RECIPIENT_LIST_DESTINATIONS {
                    return Err(past_the_cap(list.len()));
                }
                let PropertyValue::List(fields) = entry else {
                    return Err(common::invalid_data_type_error());
                };
                list.push(
                    destination_from_flat_fields(&fields)
                        .ok_or_else(common::invalid_data_type_error)?,
                );
            }
        }
        _ => return Err(common::invalid_data_type_error()),
    }
    Ok(list)
}
