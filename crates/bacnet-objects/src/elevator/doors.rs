//! Car_Door_Status and Landing_Door_Status of the Lift (Clause 12.59,
//! Table 12-77): one BACnetDoorStatus, and one BACnetLandingDoorStatus, per
//! car door.
//!
//! Item (c) of the Lift's Out_Of_Service description makes both writable
//! while the object is out of service, so a test tool can simulate the car.
//! In service they stay read-only over the network. A write takes the whole
//! array or one element. The size is the number of car doors, which the
//! application sets with `LiftObject::set_car_door_status`, so it isn't
//! writable over the network: a write of index 0 is WRITE_ACCESS_DENIED and
//! a whole-array write of another size is VALUE_OUT_OF_RANGE, as for the
//! Staging arrays. That also keeps the two arrays the same size, as Clause
//! 12.59 requires of the per-door arrays.
//!
//! An element arrives as one Enumerated for Car_Door_Status, and as one
//! `ApplicationData` holding a landing-doors frame for Landing_Door_Status; a
//! whole array arrives as a `List` of them, or, from the service decoder, as
//! the bare element when the car has one door. Error pairings follow Clause
//! 15.9.1.3: a value of the wrong shape is INVALID_DATA_TYPE, a frame that
//! doesn't decode as exactly one BACnetLandingDoorStatus is
//! INVALID_DATA_ENCODING, and a door status outside BACnetDoorStatus or a
//! well-formed floor number above 255 is VALUE_OUT_OF_RANGE. A refused write
//! changes nothing.

use bacnet_encoding::constructed::decode_landing_door_status;
use bacnet_types::constructed::BACnetLandingDoorStatus;
use bacnet_types::enums::DoorStatus;
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use super::named_or_proprietary;
use crate::common;

/// Whether `status` is in BACnetDoorStatus: a named value, or the
/// proprietary range 1024..=65535 (Clause 23.1).
pub(super) fn door_status_in_range(status: DoorStatus) -> bool {
    named_or_proprietary(DoorStatus::ALL_NAMED, status, status.to_raw())
}

/// Whether every landing door of `car_door` has a status in BACnetDoorStatus.
pub(super) fn landing_doors_in_range(car_door: &BACnetLandingDoorStatus) -> bool {
    car_door
        .landing_doors
        .iter()
        .all(|landing| door_status_in_range(landing.door_status))
}

/// Decode one Car_Door_Status element of a write.
pub(super) fn decode_car_door(value: PropertyValue) -> Result<DoorStatus, Error> {
    let PropertyValue::Enumerated(raw) = value else {
        return Err(common::invalid_data_type_error());
    };
    let status = DoorStatus::from_raw(raw);
    if !door_status_in_range(status) {
        return Err(common::value_out_of_range_error());
    }
    Ok(status)
}

/// Decode one Landing_Door_Status element of a write.
pub(super) fn decode_landing_doors(value: PropertyValue) -> Result<BACnetLandingDoorStatus, Error> {
    let PropertyValue::ApplicationData(bytes) = value else {
        return Err(common::invalid_data_type_error());
    };
    // The codec reports a well-formed but oversized member as a local
    // OutOfRange error; every other failure is a malformed encoding.
    let (car_door, consumed) =
        decode_landing_door_status(&bytes, 0).map_err(|error| match error {
            Error::OutOfRange(_) => common::value_out_of_range_error(),
            _ => common::invalid_data_encoding_error(),
        })?;
    if consumed != bytes.len() {
        return Err(common::invalid_data_encoding_error());
    }
    if !landing_doors_in_range(&car_door) {
        return Err(common::value_out_of_range_error());
    }
    Ok(car_door)
}

/// The array a write of `value` at `array_index` leaves, starting from
/// `current`, with each element decoded by `decode`. The caller stores it.
pub(super) fn written_array<T: Clone>(
    current: &[T],
    array_index: Option<u32>,
    value: PropertyValue,
    decode: fn(PropertyValue) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    match array_index {
        None => {
            let elements = match value {
                PropertyValue::List(elements) => elements,
                element => vec![element],
            };
            let array = elements
                .into_iter()
                .map(decode)
                .collect::<Result<Vec<_>, _>>()?;
            if array.len() != current.len() {
                return Err(common::value_out_of_range_error());
            }
            Ok(array)
        }
        Some(0) => Err(common::write_access_denied_error()),
        Some(index) => {
            let mut array = current.to_vec();
            let element = usize::try_from(index - 1)
                .ok()
                .and_then(|slot| array.get_mut(slot))
                .ok_or_else(common::invalid_array_index_error)?;
            *element = decode(value)?;
            Ok(array)
        }
    }
}
