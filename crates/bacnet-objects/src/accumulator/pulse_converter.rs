//! Pulse Converter (type 24) object, per ASHRAE 135-2020 §12.23 Table 12-27.
//!
//! Count holds the input pulses. In service, Present_Value is Count times
//! Scale_Factor, worked out on each read; Out_Of_Service decouples it and
//! makes it writable. A write of Adjust_Value takes the whole quotient of the
//! value over Scale_Factor off Count, keeping the old Count in
//! Count_Before_Change and the time in Count_Change_Time. `add_pulses`
//! accumulates input and stamps Update_Time.

use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::{EventState, ObjectType, PropertyIdentifier, Reliability};
use bacnet_types::error::Error;
use bacnet_types::primitives::{Date, ObjectIdentifier, PropertyValue, StatusFlags, Time};
use std::borrow::Cow;
use std::sync::Arc;

use crate::clock::{stamp_datetime, ClockReader, UNSPECIFIED_DATETIME};
use crate::common::{self, read_common_properties};
use crate::reference::{self, ReferenceFrame};
use crate::traits::BACnetObject;

mod metadata;

/// BACnet Pulse Converter object — converts accumulated pulses to an analog value.
pub struct PulseConverterObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    /// Present_Value while Out_Of_Service is TRUE. In service, Present_Value
    /// is derived from Count and this copy is unused.
    decoupled_present_value: f32,
    units: u32,
    scale_factor: f32,
    adjust_value: f32,
    /// Count; `count` times `scale_factor` always fits a finite REAL.
    count: u64,
    update_time: (Date, Time),
    count_change_time: (Date, Time),
    count_before_change: u64,
    cov_increment: f32,
    input_reference: Option<BACnetObjectPropertyReference>,
    status_flags: StatusFlags,
    event_state: EventState,
    out_of_service: bool,
    reliability: Reliability,
    /// Database-owned clock used to stamp Update_Time and Count_Change_Time.
    clock: Option<Arc<dyn ClockReader>>,
}

impl PulseConverterObject {
    /// Create a new Pulse Converter object with default values.
    pub fn new(instance: u32, name: impl Into<String>, units: u32) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::PULSE_CONVERTER, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            decoupled_present_value: 0.0,
            units,
            scale_factor: 1.0,
            adjust_value: 0.0,
            count: 0,
            update_time: UNSPECIFIED_DATETIME,
            count_change_time: UNSPECIFIED_DATETIME,
            count_before_change: 0,
            cov_increment: 0.0,
            input_reference: None,
            status_flags: StatusFlags::empty(),
            event_state: EventState::NORMAL,
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            clock: None,
        })
    }

    /// Set the description string.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Set Input_Reference, the property the input is counted from. A
    /// reference to the reserved instance 4194303 clears it, as a client's
    /// write of the unset form does (#1417).
    pub fn set_input_reference(&mut self, r: BACnetObjectPropertyReference) {
        self.input_reference = reference::set_or_unset(r);
    }

    /// The current Count.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Accumulate `pulses` input pulses into Count (Clause 12.23.14).
    ///
    /// Count is read-only over the network, so this is how the application
    /// feeds it, whether from a physical input or from the property
    /// Input_Reference names. A change stamps Update_Time from the Device
    /// clock (unspecified fields without one). Count keeps accumulating while
    /// Out_Of_Service is TRUE; only Present_Value stops following it. A sum
    /// past the largest Unsigned this object holds, or one that would scale
    /// past the largest REAL, is refused with VALUE_OUT_OF_RANGE and nothing
    /// changes. Zero pulses change nothing.
    pub fn add_pulses(&mut self, pulses: u64) -> Result<(), Error> {
        if pulses == 0 {
            return Ok(());
        }
        let count = self
            .count
            .checked_add(pulses)
            .ok_or_else(common::value_out_of_range_error)?;
        scaled(count, self.scale_factor)?;
        self.count = count;
        self.update_time = stamp_datetime(self.clock.as_deref());
        Ok(())
    }

    /// Present_Value: Count times Scale_Factor in service, or the decoupled
    /// copy while Out_Of_Service is TRUE.
    fn present_value(&self) -> f32 {
        if self.out_of_service {
            self.decoupled_present_value
        } else {
            // Every change to Count or Scale_Factor checked this product.
            scaled(self.count, self.scale_factor).unwrap_or_default()
        }
    }

    /// Apply a write of Adjust_Value as one step (Clause 12.23.13): store it,
    /// keep Count in Count_Before_Change, take the truncated quotient of the
    /// value over Scale_Factor off Count, and stamp Count_Change_Time.
    ///
    /// A Count that would leave the Unsigned range, a quotient that is not a
    /// number (a zero Scale_Factor), or a new Count that no longer scales to
    /// a finite REAL is refused with VALUE_OUT_OF_RANGE before anything
    /// changes.
    fn adjust(&mut self, adjust_value: f32) -> Result<(), Error> {
        common::reject_non_finite(adjust_value)?;
        let quotient = (f64::from(adjust_value) / f64::from(self.scale_factor)).trunc();
        // Any quotient this large moves Count out of the u64 range anyway.
        if !quotient.is_finite() || quotient.abs() > u64::MAX as f64 {
            return Err(common::value_out_of_range_error());
        }
        let count = u64::try_from(i128::from(self.count) - quotient as i128)
            .map_err(|_| common::value_out_of_range_error())?;
        scaled(count, self.scale_factor)?;
        self.adjust_value = adjust_value;
        self.count_before_change = self.count;
        self.count = count;
        self.count_change_time = stamp_datetime(self.clock.as_deref());
        Ok(())
    }
}

/// Count times Scale_Factor as a REAL, refused with VALUE_OUT_OF_RANGE when
/// the product is too large for one.
fn scaled(count: u64, scale_factor: f32) -> Result<f32, Error> {
    let value = (count as f64 * f64::from(scale_factor)) as f32;
    if value.is_finite() {
        Ok(value)
    } else {
        Err(common::value_out_of_range_error())
    }
}

fn datetime_value((date, time): (Date, Time)) -> PropertyValue {
    PropertyValue::List(vec![PropertyValue::Date(date), PropertyValue::Time(time)])
}

impl BACnetObject for PulseConverterObject {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }

    fn object_name(&self) -> &str {
        &self.name
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        if let Some(result) = read_common_properties!(self, property, array_index) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => Ok(PropertyValue::Enumerated(
                ObjectType::PULSE_CONVERTER.to_raw(),
            )),
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Real(self.present_value()))
            }
            p if p == PropertyIdentifier::UNITS => Ok(PropertyValue::Enumerated(self.units)),
            p if p == PropertyIdentifier::SCALE_FACTOR => {
                Ok(PropertyValue::Real(self.scale_factor))
            }
            p if p == PropertyIdentifier::ADJUST_VALUE => {
                Ok(PropertyValue::Real(self.adjust_value))
            }
            p if p == PropertyIdentifier::COUNT => Ok(PropertyValue::Unsigned(self.count)),
            p if p == PropertyIdentifier::UPDATE_TIME => Ok(datetime_value(self.update_time)),
            p if p == PropertyIdentifier::COUNT_CHANGE_TIME => {
                Ok(datetime_value(self.count_change_time))
            }
            p if p == PropertyIdentifier::COUNT_BEFORE_CHANGE => {
                Ok(PropertyValue::Unsigned(self.count_before_change))
            }
            p if p == PropertyIdentifier::COV_INCREMENT => {
                Ok(PropertyValue::Real(self.cov_increment))
            }
            // Periodic COV notifications are not implemented, and zero is the
            // value that says so (Clause 13.1).
            p if p == PropertyIdentifier::COV_PERIOD => Ok(PropertyValue::Unsigned(0)),
            // The reference's Clause 21 encoding (#1312), or while unset an
            // Accumulator's Present_Value, the usual input (Clause 12.23.6),
            // at the reserved instance (#1417).
            p if p == PropertyIdentifier::INPUT_REFERENCE => {
                Ok(reference::object_property_reference_value(
                    self.input_reference.as_ref(),
                    ObjectType::ACCUMULATOR,
                ))
            }
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        let in_service_value = self.present_value();
        let was_out_of_service = self.out_of_service;
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            // Going out of service freezes Present_Value where it was; writes
            // then land on the decoupled copy.
            if self.out_of_service && !was_out_of_service {
                self.decoupled_present_value = in_service_value;
            }
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        if let Some(result) = common::write_cov_increment(&mut self.cov_increment, property, &value)
        {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                if !self.out_of_service {
                    return Err(common::write_access_denied_error());
                }
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    self.decoupled_present_value = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::SCALE_FACTOR => {
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    scaled(self.count, v)?;
                    self.scale_factor = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::ADJUST_VALUE => {
                if let PropertyValue::Real(v) = value {
                    self.adjust(v)
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            // Input_Reference is BACnetObjectPropertyReference (Table
            // 12-27): its context-tagged members, the unset form clearing it.
            p if p == PropertyIdentifier::INPUT_REFERENCE => {
                self.input_reference =
                    reference::decode_reference_write(&value, ReferenceFrame::Bare)?;
                Ok(())
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_pulse_converter_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn supports_cov(&self) -> bool {
        true
    }

    fn cov_increment(&self) -> Option<f64> {
        Some(f64::from(self.cov_increment))
    }

    fn bind_clock_internal(&mut self, clock: Option<Arc<dyn ClockReader>>) {
        self.clock = clock;
    }
}

#[cfg(test)]
#[path = "../pulse_converter_policy_tests.rs"]
mod pulse_converter_policy_tests;

#[cfg(test)]
mod tests;
