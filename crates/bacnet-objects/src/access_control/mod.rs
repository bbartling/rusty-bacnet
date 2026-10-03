//! Access Control objects (ASHRAE 135-2020 Clause 12).
//!
//! This module implements the seven BACnet access control object types:
//! - AccessDoor (type 30)
//! - AccessCredential (type 32)
//! - AccessPoint (type 33)
//! - AccessRights (type 34)
//! - AccessUser (type 35)
//! - AccessZone (type 36)
//! - CredentialDataInput (type 37)

use bacnet_encoding::constructed::encode_device_object_reference;
use bacnet_encoding::primitives::encode_timestamp_choice;
use bacnet_types::constructed::BACnetDeviceObjectReference;
use bacnet_types::enums::{
    AccessEvent, AccessUserType, BinaryPV, DoorAlarmState, DoorSecuredStatus, DoorStatus,
    DoorValue, EventState, LockStatus, ObjectType, PropertyIdentifier, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{
    BACnetTimeStamp, Date, ObjectIdentifier, PropertyValue, StatusFlags, Time,
};
use bytes::BytesMut;
use std::borrow::Cow;

use crate::common::{self, read_common_properties};
use crate::traits::BACnetObject;

/// The time stamp an Access Point's Access_Event_Time and a Credential Data
/// Input's Update_Time hold before their first update: the date-and-time form
/// with every octet unspecified (Clauses 12.31.29 and 12.36.11).
fn never_updated() -> BACnetTimeStamp {
    BACnetTimeStamp::DateTime {
        date: Date {
            year: Date::UNSPECIFIED,
            month: Date::UNSPECIFIED,
            day: Date::UNSPECIFIED,
            day_of_week: Date::UNSPECIFIED,
        },
        time: Time {
            hour: Time::UNSPECIFIED,
            minute: Time::UNSPECIFIED,
            second: Time::UNSPECIFIED,
            hundredths: Time::UNSPECIFIED,
        },
    }
}

/// A `BACnetTimeStamp` property in its Clause 21 CHOICE form.
fn timestamp_value(stamp: &BACnetTimeStamp) -> Result<PropertyValue, Error> {
    let mut buf = BytesMut::new();
    encode_timestamp_choice(&mut buf, stamp)?;
    Ok(PropertyValue::ApplicationData(buf.to_vec()))
}

/// The elements of a BACnetARRAY of BACnetDeviceObjectReference (an Access
/// Door's Door_Members, an Access Point's Access_Doors), each in its Clause 21
/// form, for `common::read_array`.
fn device_object_references(references: &[BACnetDeviceObjectReference]) -> Vec<PropertyValue> {
    references
        .iter()
        .map(|reference| {
            let mut buf = BytesMut::new();
            encode_device_object_reference(&mut buf, reference);
            PropertyValue::ApplicationData(buf.to_vec())
        })
        .collect()
}

/// A client's simulated Reliability, written while Out_Of_Service is TRUE:
/// an Enumerated inside the BACnetReliability production. Another datatype is
/// INVALID_DATA_TYPE and another number VALUE_OUT_OF_RANGE.
fn simulated_reliability(value: &PropertyValue) -> Result<Reliability, Error> {
    let PropertyValue::Enumerated(raw) = value else {
        return Err(common::invalid_data_type_error());
    };
    checked_reliability(Reliability::from_raw(*raw))
}

/// `reliability`, or VALUE_OUT_OF_RANGE outside the BACnetReliability
/// production.
fn checked_reliability(reliability: Reliability) -> Result<Reliability, Error> {
    if common::is_reliability_value_valid(reliability) {
        Ok(reliability)
    } else {
        Err(common::value_out_of_range_error())
    }
}

// ---------------------------------------------------------------------------

mod credential;
mod credential_data_input;
mod credential_data_input_formats;
mod credential_data_input_out_of_service;
mod credential_rules;
mod door;
mod door_out_of_service;
mod metadata_identity;
mod metadata_topology;
mod point;
mod rights;
mod user;
mod zone;
mod zone_out_of_service;
pub use credential::*;
pub use credential_data_input::*;
pub use door::*;
pub use point::*;
pub use rights::*;
pub use user::*;
pub use zone::*;

#[cfg(test)]
mod array_tests;
#[cfg(test)]
mod constructed_value_tests;
#[cfg(test)]
mod credential_data_input_format_tests;
#[cfg(test)]
mod credential_data_input_out_of_service_tests;
#[cfg(test)]
mod credential_tests;
#[cfg(test)]
mod door_out_of_service_tests;
#[cfg(test)]
mod door_pulse_tests;
#[cfg(test)]
mod point_out_of_service_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod typed_value_tests;
#[cfg(test)]
mod zone_out_of_service_tests;
