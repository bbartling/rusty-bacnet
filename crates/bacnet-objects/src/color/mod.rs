//! Color (type 63) and Color Temperature (type 64) objects, added by
//! Addendum 135-2020ca.
//!
//! Color objects represent CIE 1931 xy color coordinates.
//! Color Temperature objects represent correlated color temperature in Kelvin.
//! Both take a typed `BACnetColorCommand` as Color_Command, checked against
//! the operations each allows (see `command`), and serve the last one taken.
//! Neither carries a command out: Present_Value, Tracking_Value and
//! In_Progress stay as they are.

use bacnet_types::constructed::{BACnetColorCommand, BACnetXyColor};
use bacnet_types::enums::{
    ColorOperation, EventState, ObjectType, PropertyIdentifier, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use std::borrow::Cow;

use crate::common::{self, read_common_properties, read_property_list_property};
use crate::traits::BACnetObject;

mod command;
mod metadata;

#[cfg(test)]
mod command_tests;

/// D65 white, where a new Color object starts.
const D65: BACnetXyColor = BACnetXyColor::new(0.3127, 0.3290);

/// The value an xy colour reads as: its two REALs, which encode as the
/// BACnetxyColor SEQUENCE.
fn xy_value(color: BACnetXyColor) -> PropertyValue {
    PropertyValue::List(vec![
        PropertyValue::Real(color.x),
        PropertyValue::Real(color.y),
    ])
}

// ---------------------------------------------------------------------------
// ColorObject (type 63) — CIE 1931 xy color
// ---------------------------------------------------------------------------

/// BACnet Color object (type 63).
///
/// Represents a color as CIE 1931 xy coordinates. Non-commandable (no
/// priority array).
///
/// Color_Command takes a [`BACnetColorCommand`] whose operation is
/// FADE_TO_COLOR or STOP (see [`set_color_command`](Self::set_color_command))
/// and serves the last one taken. The object doesn't carry commands out.
pub struct ColorObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    /// Present_Value: the target colour.
    present_value: BACnetXyColor,
    /// Tracking_Value: current actual color (may differ during fade).
    tracking_value: BACnetXyColor,
    /// The last command written; operation NONE until then.
    color_command: BACnetColorCommand,
    /// Default_Color: startup color.
    default_color: BACnetXyColor,
    /// Default_Fade_Time: milliseconds (100-86400000). 0 = use device default.
    default_fade_time: u32,
    /// Transition: 0=NONE, 1=FADE.
    transition: u32,
    /// In_Progress: 0=idle, 1=fade-active.
    in_progress: u32,
    status_flags: StatusFlags,
    event_state: EventState,
    out_of_service: bool,
    reliability: Reliability,
}

impl ColorObject {
    /// Create a new Color object with default white color (x=0.3127, y=0.3290 ≈ D65).
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::COLOR, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: D65,
            tracking_value: D65,
            color_command: BACnetColorCommand::new(ColorOperation::NONE),
            default_color: D65,
            default_fade_time: 0,
            transition: 0,  // NONE
            in_progress: 0, // idle
            status_flags: StatusFlags::empty(),
            event_state: EventState::NORMAL,
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }

    /// Set the CIE 1931 xy Present_Value and make Tracking_Value follow it immediately.
    pub fn set_present_value(&mut self, x: f32, y: f32) {
        self.present_value = BACnetXyColor::new(x, y);
        self.tracking_value = self.present_value;
    }

    /// The last command written to Color_Command, or operation NONE with no
    /// other field before any write.
    pub fn color_command(&self) -> BACnetColorCommand {
        self.color_command
    }

    /// Set Color_Command, as a WriteProperty of the encoded command would.
    ///
    /// The command is checked against the Color object's table of colour
    /// commands (Addendum 135-2020ca): only FADE_TO_COLOR and STOP are taken.
    /// FADE_TO_COLOR needs a target colour with both coordinates 0.0 to 1.0,
    /// and a fade time, when it carries one, of 100 to 86,400,000 ms. Fields
    /// the operation doesn't use are kept unchecked. A refusal is
    /// VALUE_OUT_OF_RANGE and leaves the property unchanged. The object
    /// stores the command without carrying it out.
    pub fn set_color_command(&mut self, command: BACnetColorCommand) -> Result<(), Error> {
        command::check_color(&command)?;
        self.color_command = command;
        Ok(())
    }
}

impl BACnetObject for ColorObject {
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
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::COLOR.to_raw()))
            }
            p if p == PropertyIdentifier::PRESENT_VALUE => Ok(xy_value(self.present_value)),
            p if p == PropertyIdentifier::TRACKING_VALUE => Ok(xy_value(self.tracking_value)),
            p if p == PropertyIdentifier::COLOR_COMMAND => Ok(command::encode(&self.color_command)),
            p if p == PropertyIdentifier::DEFAULT_COLOR => Ok(xy_value(self.default_color)),
            p if p == PropertyIdentifier::DEFAULT_FADE_TIME => {
                Ok(PropertyValue::Unsigned(self.default_fade_time as u64))
            }
            p if p == PropertyIdentifier::TRANSITION => {
                Ok(PropertyValue::Enumerated(self.transition))
            }
            p if p == PropertyIdentifier::IN_PROGRESS => {
                Ok(PropertyValue::Enumerated(self.in_progress))
            }
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            p if p == PropertyIdentifier::PROPERTY_LIST => {
                read_property_list_property(&self.property_list(), array_index)
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
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::COLOR_COMMAND => {
                self.color_command = command::decode_write(value, command::check_color)?;
                Ok(())
            }
            p if p == PropertyIdentifier::DEFAULT_FADE_TIME => {
                if let PropertyValue::Unsigned(v) = value {
                    if v > 86_400_000 {
                        return Err(common::value_out_of_range_error());
                    }
                    self.default_fade_time = v as u32;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_color_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn supports_cov(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// ColorTemperatureObject (type 64) — Correlated Color Temperature
// ---------------------------------------------------------------------------

/// BACnet Color Temperature object (type 64).
///
/// Represents correlated color temperature in Kelvin (typically 1000-30000).
///
/// Color_Command takes a [`BACnetColorCommand`] whose operation is
/// FADE_TO_CCT, RAMP_TO_CCT, STEP_UP_CCT, STEP_DOWN_CCT or STOP (see
/// [`set_color_command`](Self::set_color_command)) and serves the last one
/// taken. The object doesn't carry commands out.
pub struct ColorTemperatureObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    /// Present_Value: Unsigned (Kelvin).
    present_value: u32,
    /// Tracking_Value: current actual color temperature.
    tracking_value: u32,
    /// The last command written; operation NONE until then.
    color_command: BACnetColorCommand,
    /// Default_Color_Temperature: startup value.
    default_color_temperature: u32,
    /// Default_Fade_Time: milliseconds.
    default_fade_time: u32,
    /// Default_Ramp_Rate: Kelvin per second.
    default_ramp_rate: u32,
    /// Default_Step_Increment: Kelvin per step.
    default_step_increment: u32,
    /// Transition: 0=NONE, 1=FADE, 2=RAMP.
    transition: u32,
    /// In_Progress: 0=idle, 1=fade-active, 2=ramp-active.
    in_progress: u32,
    /// Min/Max present value bounds.
    min_pres_value: Option<u32>,
    max_pres_value: Option<u32>,
    status_flags: StatusFlags,
    event_state: EventState,
    out_of_service: bool,
    reliability: Reliability,
}

impl ColorTemperatureObject {
    /// Create a new Color Temperature object with default 4000K (neutral white).
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::COLOR_TEMPERATURE, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: 4000,
            tracking_value: 4000,
            color_command: BACnetColorCommand::new(ColorOperation::NONE),
            default_color_temperature: 4000,
            default_fade_time: 0,
            default_ramp_rate: 100,     // 100K/s
            default_step_increment: 50, // 50K per step
            transition: 0,              // NONE
            in_progress: 0,             // idle
            min_pres_value: Some(1000),
            max_pres_value: Some(30000),
            status_flags: StatusFlags::empty(),
            event_state: EventState::NORMAL,
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
        })
    }

    /// Set Present_Value in kelvin and make Tracking_Value follow it immediately.
    pub fn set_present_value(&mut self, kelvin: u32) {
        self.present_value = kelvin;
        self.tracking_value = kelvin;
    }

    /// Set the Min_Pres_Value and Max_Pres_Value limits, in kelvin.
    pub fn set_min_max(&mut self, min: u32, max: u32) {
        self.min_pres_value = Some(min);
        self.max_pres_value = Some(max);
    }

    /// The last command written to Color_Command, or operation NONE with no
    /// other field before any write.
    pub fn color_command(&self) -> BACnetColorCommand {
        self.color_command
    }

    /// Set Color_Command, as a WriteProperty of the encoded command would.
    ///
    /// The command is checked against the Color Temperature object's table
    /// of colour commands (Addendum 135-2020ca): FADE_TO_CCT, RAMP_TO_CCT,
    /// STEP_UP_CCT, STEP_DOWN_CCT and STOP are taken. FADE_TO_CCT and
    /// RAMP_TO_CCT need a target colour temperature of 1000 to 30000 K. A
    /// field the operation uses must be in range: fade time (FADE_TO_CCT) 100
    /// to 86,400,000 ms, ramp rate (RAMP_TO_CCT) 1 to 30000 K/s, step
    /// increment (the step operations) 1 to 30000 K. Fields the operation
    /// doesn't use are kept unchecked. A refusal is VALUE_OUT_OF_RANGE and
    /// leaves the property unchanged. The object stores the command without
    /// carrying it out.
    pub fn set_color_command(&mut self, command: BACnetColorCommand) -> Result<(), Error> {
        command::check_color_temperature(&command)?;
        self.color_command = command;
        Ok(())
    }
}

impl BACnetObject for ColorTemperatureObject {
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
                ObjectType::COLOR_TEMPERATURE.to_raw(),
            )),
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Unsigned(self.present_value as u64))
            }
            p if p == PropertyIdentifier::TRACKING_VALUE => {
                Ok(PropertyValue::Unsigned(self.tracking_value as u64))
            }
            p if p == PropertyIdentifier::COLOR_COMMAND => Ok(command::encode(&self.color_command)),
            p if p == PropertyIdentifier::DEFAULT_COLOR_TEMPERATURE => Ok(PropertyValue::Unsigned(
                self.default_color_temperature as u64,
            )),
            p if p == PropertyIdentifier::DEFAULT_FADE_TIME => {
                Ok(PropertyValue::Unsigned(self.default_fade_time as u64))
            }
            p if p == PropertyIdentifier::DEFAULT_RAMP_RATE => {
                Ok(PropertyValue::Unsigned(self.default_ramp_rate as u64))
            }
            p if p == PropertyIdentifier::DEFAULT_STEP_INCREMENT => {
                Ok(PropertyValue::Unsigned(self.default_step_increment as u64))
            }
            p if p == PropertyIdentifier::TRANSITION => {
                Ok(PropertyValue::Enumerated(self.transition))
            }
            p if p == PropertyIdentifier::IN_PROGRESS => {
                Ok(PropertyValue::Enumerated(self.in_progress))
            }
            p if p == PropertyIdentifier::MIN_PRES_VALUE => match self.min_pres_value {
                Some(v) => Ok(PropertyValue::Unsigned(v as u64)),
                None => Err(common::unknown_property_error()),
            },
            p if p == PropertyIdentifier::MAX_PRES_VALUE => match self.max_pres_value {
                Some(v) => Ok(PropertyValue::Unsigned(v as u64)),
                None => Err(common::unknown_property_error()),
            },
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            p if p == PropertyIdentifier::PROPERTY_LIST => {
                read_property_list_property(&self.property_list(), array_index)
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
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                if let PropertyValue::Unsigned(v) = value {
                    let v32 = common::u64_to_u32(v)?;
                    // Clamp to min/max if supported
                    if let Some(min) = self.min_pres_value {
                        if v32 < min {
                            return Err(common::value_out_of_range_error());
                        }
                    }
                    if let Some(max) = self.max_pres_value {
                        if v32 > max {
                            return Err(common::value_out_of_range_error());
                        }
                    }
                    self.present_value = v32;
                    self.tracking_value = v32;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::COLOR_COMMAND => {
                self.color_command =
                    command::decode_write(value, command::check_color_temperature)?;
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
        metadata::for_color_temperature_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn supports_cov(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_types::enums::{ErrorClass, ErrorCode};

    fn assert_property_error(error: Error, expected_code: ErrorCode) {
        match error {
            Error::Protocol { class, code } => {
                assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
                assert_eq!(code, expected_code.to_raw() as u32);
            }
            other => panic!("expected PROPERTY/{expected_code:?}, got {other:?}"),
        }
    }

    fn assert_present_and_tracking(object: &ColorTemperatureObject, expected: u64) {
        assert_eq!(
            object
                .read_property(PropertyIdentifier::PRESENT_VALUE, None)
                .unwrap(),
            PropertyValue::Unsigned(expected)
        );
        assert_eq!(
            object
                .read_property(PropertyIdentifier::TRACKING_VALUE, None)
                .unwrap(),
            PropertyValue::Unsigned(expected)
        );
    }

    #[test]
    fn color_temperature_rejects_overwide_present_value_without_mutation() {
        let mut object = ColorTemperatureObject::new(1, "CT-1").unwrap();

        let error = object
            .write_property(
                PropertyIdentifier::PRESENT_VALUE,
                None,
                PropertyValue::Unsigned(0x1_0000_03E8),
                None,
            )
            .expect_err("over-wide Present_Value must be rejected");

        assert_property_error(error, ErrorCode::VALUE_OUT_OF_RANGE);
        assert_present_and_tracking(&object, 4000);
    }

    #[test]
    fn color_temperature_preserves_present_value_boundaries() {
        let mut object = ColorTemperatureObject::new(1, "CT-1").unwrap();

        for value in [1000, 30000] {
            object
                .write_property(
                    PropertyIdentifier::PRESENT_VALUE,
                    None,
                    PropertyValue::Unsigned(value),
                    None,
                )
                .unwrap();
            assert_present_and_tracking(&object, value);
        }

        let error = object
            .write_property(
                PropertyIdentifier::PRESENT_VALUE,
                None,
                PropertyValue::Unsigned(u32::MAX as u64),
                None,
            )
            .expect_err("u32::MAX remains outside the configured range");
        assert_property_error(error, ErrorCode::VALUE_OUT_OF_RANGE);
        assert_present_and_tracking(&object, 30000);

        let error = object
            .write_property(
                PropertyIdentifier::PRESENT_VALUE,
                None,
                PropertyValue::Real(1000.0),
                None,
            )
            .expect_err("wrong datatype must be rejected");
        assert_property_error(error, ErrorCode::INVALID_DATA_TYPE);
        assert_present_and_tracking(&object, 30000);
    }
}
