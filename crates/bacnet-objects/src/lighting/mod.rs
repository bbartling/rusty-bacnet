//! Lighting Output (type 54) and Binary Lighting Output (type 55) objects per
//! ASHRAE 135-2020 Clauses 12.54 and 12.55.

use bacnet_types::constructed::BACnetLightingCommand;
use bacnet_types::enums::{LightingOperation, ObjectType, PropertyIdentifier, Reliability};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use std::borrow::Cow;

use crate::common::{self, read_common_properties, read_priority_array, write_priority_array};
use crate::traits::BACnetObject;

// ---------------------------------------------------------------------------
// LightingOutput (type 54)
// ---------------------------------------------------------------------------

/// BACnet Lighting Output object.
///
/// Commandable output with a 16-level priority array controlling a
/// floating-point present-value (0.0 to 100.0 percent).
///
/// Lighting_Command takes a [`BACnetLightingCommand`] checked against its
/// operation (see [`set_lighting_command`](Self::set_lighting_command)) and
/// serves the last one taken. The object doesn't carry commands out: a
/// command leaves Present_Value, Tracking_Value, In_Progress and the
/// priority array as they are.
pub struct LightingOutputObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    present_value: f32,
    tracking_value: f32,
    /// The last command written; operation NONE until then.
    lighting_command: BACnetLightingCommand,
    lighting_command_default_priority: u32,
    /// LightingInProgress enumeration: 0=idle, 1=fade-active, 2=ramp-active, 3=not-controlled, etc.
    in_progress: u32,
    blink_warn_enable: bool,
    egress_time: u32,
    egress_active: bool,
    /// Default_Fade_Time in milliseconds, within 100..=86_400_000.
    default_fade_time: u32,
    /// Default_Ramp_Rate in percent per second, within 0.1..=100.0.
    default_ramp_rate: f32,
    /// Default_Step_Increment in percent, within 0.1..=100.0.
    default_step_increment: f32,
    /// COV_Increment: the Present_Value change that triggers a notification.
    cov_increment: f32,
    out_of_service: bool,
    status_flags: StatusFlags,
    /// Reliability; NO_FAULT_DETECTED until a fault is evaluated or simulated.
    reliability: Reliability,
    priority_array: [Option<f32>; 16],
    relinquish_default: f32,
}

impl LightingOutputObject {
    /// Create a new Lighting Output object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::LIGHTING_OUTPUT, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: 0.0,
            tracking_value: 0.0,
            lighting_command: BACnetLightingCommand::new(LightingOperation::NONE),
            lighting_command_default_priority: 16,
            in_progress: 0, // idle
            blink_warn_enable: false,
            egress_time: 0,
            egress_active: false,
            default_fade_time: *DEFAULT_FADE_TIME_MS.start(),
            default_ramp_rate: 100.0,
            default_step_increment: 1.0,
            cov_increment: 0.0,
            out_of_service: false,
            status_flags: StatusFlags::empty(),
            reliability: Reliability::NO_FAULT_DETECTED,
            priority_array: [None; 16],
            relinquish_default: 0.0,
        })
    }

    /// Set the description string.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Recalculate present-value from the priority array.
    fn recalculate_present_value(&mut self) {
        self.present_value =
            common::recalculate_from_priority_array(&self.priority_array, self.relinquish_default);
    }

    /// Set the Relinquish_Default (#270).
    ///
    /// Validated the same way a commanded Present_Value is (finite Real
    /// within the 0..=100 light level); after the store, Present_Value is
    /// resolved anew from the priority array so an empty array falls back to
    /// the new default immediately.
    pub fn set_relinquish_default(&mut self, value: f32) -> Result<(), Error> {
        if !value.is_finite() || !(0.0..=100.0).contains(&value) {
            return Err(common::value_out_of_range_error());
        }
        self.relinquish_default = value;
        self.recalculate_present_value();
        Ok(())
    }

    /// The last command written to Lighting_Command, or operation NONE with no
    /// other field before any write.
    pub fn lighting_command(&self) -> BACnetLightingCommand {
        self.lighting_command
    }

    /// Set Lighting_Command, as a WriteProperty of the encoded command would.
    ///
    /// The command is checked against its operation (Clause 12.54, Table
    /// 12-67). NONE, a reserved operation (11 to 255) and anything past
    /// 65,535 are refused; FADE_TO and RAMP_TO need a target level. A field
    /// the operation uses must be in range: target level 0.0 to 100.0, fade
    /// time 100 to 86,400,000 ms, ramp rate and step increment 0.1 to 100.0,
    /// priority 1 to 16. Fields it doesn't use are kept unchecked, and a
    /// proprietary operation (256 to 65,535) has only its priority checked. A
    /// refusal is VALUE_OUT_OF_RANGE and leaves the property unchanged.
    pub fn set_lighting_command(&mut self, command: BACnetLightingCommand) -> Result<(), Error> {
        command::check(&command)?;
        self.lighting_command = command;
        Ok(())
    }

    /// Set Default_Fade_Time, the milliseconds a fade request without its own
    /// fade time takes. A new object uses 100, the shortest fade the clause
    /// allows, as Default_Ramp_Rate starts at its fastest rate.
    ///
    /// Clause 12.54.16 bounds it to 100..=86_400_000 (one day); a value
    /// outside that range is refused with VALUE_OUT_OF_RANGE and the property
    /// is left unchanged. WriteProperty applies the same check.
    pub fn set_default_fade_time(&mut self, milliseconds: u32) -> Result<(), Error> {
        if !DEFAULT_FADE_TIME_MS.contains(&milliseconds) {
            return Err(common::value_out_of_range_error());
        }
        self.default_fade_time = milliseconds;
        Ok(())
    }

    /// Set Default_Ramp_Rate, the percent-per-second rate a ramp request
    /// without its own rate uses. A new object uses 100.0.
    ///
    /// Clause 12.54.17 bounds it to 0.1..=100.0; a value outside that range,
    /// or a non-finite one, is refused with VALUE_OUT_OF_RANGE and the
    /// property is left unchanged. WriteProperty applies the same check.
    pub fn set_default_ramp_rate(&mut self, value: f32) -> Result<(), Error> {
        self.default_ramp_rate = lighting_percent(value)?;
        Ok(())
    }

    /// Set Default_Step_Increment, the percent a step request without its own
    /// increment adds. A new object uses 1.0.
    ///
    /// Clause 12.54.18 bounds it to 0.1..=100.0; a value outside that range,
    /// or a non-finite one, is refused with VALUE_OUT_OF_RANGE and the
    /// property is left unchanged. WriteProperty applies the same check.
    pub fn set_default_step_increment(&mut self, value: f32) -> Result<(), Error> {
        self.default_step_increment = lighting_percent(value)?;
        Ok(())
    }
}

/// The Default_Fade_Time range of Clause 12.54.16, in milliseconds, which a
/// lighting command's fade time shares (Table 12-66).
const DEFAULT_FADE_TIME_MS: std::ops::RangeInclusive<u32> = 100..=86_400_000;

/// Check a Default_Ramp_Rate or Default_Step_Increment value, or a lighting
/// command's ramp rate or step increment, which share the 0.1..=100.0 range.
fn lighting_percent(value: f32) -> Result<f32, Error> {
    if (0.1..=100.0).contains(&value) {
        Ok(value)
    } else {
        Err(common::value_out_of_range_error())
    }
}

impl BACnetObject for LightingOutputObject {
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
                ObjectType::LIGHTING_OUTPUT.to_raw(),
            )),
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Real(self.present_value))
            }
            p if p == PropertyIdentifier::TRACKING_VALUE => {
                Ok(PropertyValue::Real(self.tracking_value))
            }
            p if p == PropertyIdentifier::LIGHTING_COMMAND => {
                Ok(command::encode(&self.lighting_command))
            }
            p if p == PropertyIdentifier::LIGHTING_COMMAND_DEFAULT_PRIORITY => Ok(
                PropertyValue::Unsigned(self.lighting_command_default_priority as u64),
            ),
            p if p == PropertyIdentifier::IN_PROGRESS => {
                Ok(PropertyValue::Enumerated(self.in_progress))
            }
            p if p == PropertyIdentifier::BLINK_WARN_ENABLE => {
                Ok(PropertyValue::Boolean(self.blink_warn_enable))
            }
            p if p == PropertyIdentifier::EGRESS_TIME => {
                Ok(PropertyValue::Unsigned(self.egress_time as u64))
            }
            p if p == PropertyIdentifier::EGRESS_ACTIVE => {
                Ok(PropertyValue::Boolean(self.egress_active))
            }
            p if p == PropertyIdentifier::PRIORITY_ARRAY => {
                read_priority_array!(self, array_index, PropertyValue::Real)
            }
            p if p == PropertyIdentifier::RELINQUISH_DEFAULT => {
                Ok(PropertyValue::Real(self.relinquish_default))
            }
            p if p == PropertyIdentifier::DEFAULT_FADE_TIME => {
                Ok(PropertyValue::Unsigned(u64::from(self.default_fade_time)))
            }
            p if p == PropertyIdentifier::DEFAULT_RAMP_RATE => {
                Ok(PropertyValue::Real(self.default_ramp_rate))
            }
            p if p == PropertyIdentifier::DEFAULT_STEP_INCREMENT => {
                Ok(PropertyValue::Real(self.default_step_increment))
            }
            p if p == PropertyIdentifier::COV_INCREMENT => {
                Ok(PropertyValue::Real(self.cov_increment))
            }
            p if p == PropertyIdentifier::CURRENT_COMMAND_PRIORITY => {
                Ok(common::current_command_priority(&self.priority_array))
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), Error> {
        // Commands update priority slots only through Present_Value.
        if property == PropertyIdentifier::PRESENT_VALUE {
            return write_priority_array!(self, value, priority, |v| {
                match v {
                    PropertyValue::Real(f) => {
                        if !(0.0..=100.0).contains(&f) {
                            Err(common::value_out_of_range_error())
                        } else {
                            Ok(f)
                        }
                    }
                    _ => Err(common::invalid_data_type_error()),
                }
            });
        }

        // LIGHTING_COMMAND: a BACnetLightingCommand, checked against its
        // operation.
        if property == PropertyIdentifier::LIGHTING_COMMAND {
            self.lighting_command = command::decode_write(value)?;
            return Ok(());
        }

        // LIGHTING_COMMAND_DEFAULT_PRIORITY
        if property == PropertyIdentifier::LIGHTING_COMMAND_DEFAULT_PRIORITY {
            if let PropertyValue::Unsigned(v) = value {
                if !(1..=16).contains(&v) {
                    return Err(common::value_out_of_range_error());
                }
                self.lighting_command_default_priority = v as u32;
                return Ok(());
            }
            return Err(common::invalid_data_type_error());
        }

        // RELINQUISH_DEFAULT — writable per Table 12-64 (R; the standard
        // permits writability), validated the same way a commanded
        // Present_Value is by the shared setter.
        if property == PropertyIdentifier::RELINQUISH_DEFAULT {
            if let PropertyValue::Real(f) = value {
                return self.set_relinquish_default(f);
            }
            return Err(common::invalid_data_type_error());
        }

        // BLINK_WARN_ENABLE
        if property == PropertyIdentifier::BLINK_WARN_ENABLE {
            if let PropertyValue::Boolean(v) = value {
                self.blink_warn_enable = v;
                return Ok(());
            }
            return Err(common::invalid_data_type_error());
        }

        // EGRESS_TIME
        if property == PropertyIdentifier::EGRESS_TIME {
            if let PropertyValue::Unsigned(v) = value {
                self.egress_time = common::u64_to_u32(v)?;
                return Ok(());
            }
            return Err(common::invalid_data_type_error());
        }

        // DEFAULT_FADE_TIME, DEFAULT_RAMP_RATE and DEFAULT_STEP_INCREMENT go
        // through the range-checked setters. A fade time too large for the
        // setter's u32 is past the range too.
        if property == PropertyIdentifier::DEFAULT_FADE_TIME {
            if let PropertyValue::Unsigned(v) = value {
                return self.set_default_fade_time(common::u64_to_u32(v)?);
            }
            return Err(common::invalid_data_type_error());
        }
        if property == PropertyIdentifier::DEFAULT_RAMP_RATE {
            if let PropertyValue::Real(v) = value {
                return self.set_default_ramp_rate(v);
            }
            return Err(common::invalid_data_type_error());
        }
        if property == PropertyIdentifier::DEFAULT_STEP_INCREMENT {
            if let PropertyValue::Real(v) = value {
                return self.set_default_step_increment(v);
            }
            return Err(common::invalid_data_type_error());
        }

        if let Some(result) = common::write_cov_increment(&mut self.cov_increment, property, &value)
        {
            return result;
        }
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        Err(crate::common::unhandled_write_error(
            self.property_metadata().as_ref(),
            property,
            _array_index,
        ))
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_lighting_output_object(self)
    }

    fn cov_increment(&self) -> Option<f64> {
        Some(f64::from(self.cov_increment))
    }

    fn supports_cov(&self) -> bool {
        true
    }
}

mod binary;
mod command;
mod metadata;
pub use binary::BinaryLightingOutputObject;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;

#[cfg(test)]
mod required_rows_tests;

#[cfg(test)]
mod command_tests;
