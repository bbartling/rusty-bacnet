//! Loop (type 12) object per ASHRAE 135-2020 Clause 12.17.
//!
//! PID control loop. The application is responsible for running the PID
//! algorithm; this object stores configuration and current output.

use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::{
    ErrorClass, ErrorCode, EventState, ObjectType, PropertyIdentifier, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use std::borrow::Cow;

use crate::common::{self, read_property_list_property};
use crate::traits::BACnetObject;

mod metadata;

/// BACnet Loop object — PID control loop configuration and state.
pub struct LoopObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    present_value: f32,
    setpoint: f32,
    controlled_variable_value: f32,
    cov_increment: f32,
    proportional_constant: f32,
    integral_constant: f32,
    derivative_constant: f32,
    output_units: u32,
    update_interval: u32,
    out_of_service: bool,
    reliability: Reliability,
    /// Evaluated Reliability saved while a client simulation owns the property
    /// (Out_Of_Service TRUE); restored on the return to service.
    reliability_before_out_of_service: Option<Reliability>,
    status_flags: StatusFlags,
    controlled_variable_reference: Option<BACnetObjectPropertyReference>,
    manipulated_variable_reference: Option<BACnetObjectPropertyReference>,
    setpoint_reference: Option<BACnetObjectPropertyReference>,
}

impl LoopObject {
    /// Create a new Loop object; `output_units` is a raw BACnetEngineeringUnits value for the
    /// output.
    pub fn new(instance: u32, name: impl Into<String>, output_units: u32) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::LOOP, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: 0.0,
            setpoint: 0.0,
            controlled_variable_value: 0.0,
            cov_increment: 0.0,
            proportional_constant: 1.0,
            integral_constant: 0.0,
            derivative_constant: 0.0,
            output_units,
            update_interval: 1000, // milliseconds
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            reliability_before_out_of_service: None,
            status_flags: StatusFlags::empty(),
            controlled_variable_reference: None,
            manipulated_variable_reference: None,
            setpoint_reference: None,
        })
    }

    /// Application sets the current output value after PID computation.
    ///
    /// This direct setter bypasses the server's COV fanout and the
    /// Out_Of_Service guard; a running server's application uses
    /// `BACnetServer::set_present_value_local` instead.
    pub fn set_present_value(&mut self, value: f32) {
        self.present_value = value;
    }

    /// Application sets the measured value of the property that
    /// Controlled_Variable_Reference names (Clause 12.17.14).
    ///
    /// COV notifications carry the latest value, but a change of it alone
    /// sends none (Table 13-1).
    pub fn set_controlled_variable_value(&mut self, value: f32) {
        self.controlled_variable_value = value;
    }

    /// Validate and store a Present_Value write, without any access check.
    ///
    /// Shared by the network and internal routes, which differ only in the
    /// Out_Of_Service condition each requires.
    fn apply_present_value(&mut self, value: PropertyValue) -> Result<(), Error> {
        let PropertyValue::Real(v) = value else {
            return Err(common::invalid_data_type_error());
        };
        common::reject_non_finite(v)?;
        self.present_value = v;
        Ok(())
    }

    /// Set the description string.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Set the controlled variable reference (the object whose present value is
    /// being controlled by this loop).
    pub fn set_controlled_variable_reference(&mut self, r: BACnetObjectPropertyReference) {
        self.controlled_variable_reference = Some(r);
    }

    /// Set the manipulated variable reference (the object that the loop output
    /// drives to achieve the setpoint).
    pub fn set_manipulated_variable_reference(&mut self, r: BACnetObjectPropertyReference) {
        self.manipulated_variable_reference = Some(r);
    }

    /// Set the setpoint reference (an alternative way to supply the setpoint
    /// from another object's property instead of the inline `SETPOINT` value).
    pub fn set_setpoint_reference(&mut self, r: BACnetObjectPropertyReference) {
        self.setpoint_reference = Some(r);
    }
}

impl BACnetObject for LoopObject {
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
        match property {
            p if p == PropertyIdentifier::OBJECT_IDENTIFIER => {
                Ok(PropertyValue::ObjectIdentifier(self.oid))
            }
            p if p == PropertyIdentifier::OBJECT_NAME => {
                Ok(PropertyValue::CharacterString(self.name.clone()))
            }
            p if p == PropertyIdentifier::DESCRIPTION => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::LOOP.to_raw()))
            }
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Real(self.present_value))
            }
            p if p == PropertyIdentifier::SETPOINT => Ok(PropertyValue::Real(self.setpoint)),
            p if p == PropertyIdentifier::CONTROLLED_VARIABLE_VALUE => {
                Ok(PropertyValue::Real(self.controlled_variable_value))
            }
            p if p == PropertyIdentifier::COV_INCREMENT => {
                Ok(PropertyValue::Real(self.cov_increment))
            }
            p if p == PropertyIdentifier::PROPORTIONAL_CONSTANT => {
                Ok(PropertyValue::Real(self.proportional_constant))
            }
            p if p == PropertyIdentifier::INTEGRAL_CONSTANT => {
                Ok(PropertyValue::Real(self.integral_constant))
            }
            p if p == PropertyIdentifier::DERIVATIVE_CONSTANT => {
                Ok(PropertyValue::Real(self.derivative_constant))
            }
            p if p == PropertyIdentifier::OUTPUT_UNITS => {
                Ok(PropertyValue::Enumerated(self.output_units))
            }
            p if p == PropertyIdentifier::UPDATE_INTERVAL => {
                Ok(PropertyValue::Unsigned(self.update_interval as u64))
            }
            // FAULT follows Reliability and OUT_OF_SERVICE follows
            // Out_Of_Service; IN_ALARM follows the fixed NORMAL Event_State
            // this object reports.
            p if p == PropertyIdentifier::STATUS_FLAGS => Ok(common::compute_status_flags(
                self.status_flags,
                self.reliability,
                self.out_of_service,
                EventState::NORMAL,
            )),
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(EventState::NORMAL.to_raw()))
            }
            p if p == PropertyIdentifier::RELIABILITY => {
                Ok(PropertyValue::Enumerated(self.reliability.to_raw()))
            }
            p if p == PropertyIdentifier::OUT_OF_SERVICE => {
                Ok(PropertyValue::Boolean(self.out_of_service))
            }
            p if p == PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE => Ok(
                crate::reference::reference_read_value(&self.controlled_variable_reference),
            ),
            p if p == PropertyIdentifier::MANIPULATED_VARIABLE_REFERENCE => Ok(
                crate::reference::reference_read_value(&self.manipulated_variable_reference),
            ),
            p if p == PropertyIdentifier::SETPOINT_REFERENCE => Ok(
                crate::reference::reference_read_value(&self.setpoint_reference),
            ),
            p if p == PropertyIdentifier::PROPERTY_LIST => {
                read_property_list_property(&self.property_list(), array_index)
            }
            _ => Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::UNKNOWN_PROPERTY.to_raw() as u32,
            }),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        // Clause 12.17.9 decouples Present_Value from the algorithm while
        // Out_Of_Service is TRUE and Table 12-20 footnote 7 makes it writable
        // then, for simulation and testing. In service the algorithm owns it;
        // the application route is `set_present_value_internal`.
        if property == PropertyIdentifier::PRESENT_VALUE {
            if !self.out_of_service {
                return Err(common::write_access_denied_error());
            }
            return self.apply_present_value(value);
        }
        if let Some(result) = common::write_out_of_service_with_reliability_restore(
            &mut self.out_of_service,
            &mut self.reliability,
            &mut self.reliability_before_out_of_service,
            property,
            &value,
        ) {
            return result;
        }
        if let Some(result) = common::write_cov_increment(&mut self.cov_increment, property, &value)
        {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::SETPOINT => {
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    self.setpoint = v;
                    return Ok(());
                }
                Err(Error::Protocol {
                    class: ErrorClass::PROPERTY.to_raw() as u32,
                    code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
                })
            }
            p if p == PropertyIdentifier::PROPORTIONAL_CONSTANT => {
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    self.proportional_constant = v;
                    return Ok(());
                }
                Err(Error::Protocol {
                    class: ErrorClass::PROPERTY.to_raw() as u32,
                    code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
                })
            }
            p if p == PropertyIdentifier::INTEGRAL_CONSTANT => {
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    self.integral_constant = v;
                    return Ok(());
                }
                Err(Error::Protocol {
                    class: ErrorClass::PROPERTY.to_raw() as u32,
                    code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
                })
            }
            p if p == PropertyIdentifier::DERIVATIVE_CONSTANT => {
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    self.derivative_constant = v;
                    return Ok(());
                }
                Err(Error::Protocol {
                    class: ErrorClass::PROPERTY.to_raw() as u32,
                    code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
                })
            }
            p if p == PropertyIdentifier::UPDATE_INTERVAL => {
                if let PropertyValue::Unsigned(v) = value {
                    self.update_interval = common::u64_to_u32(v)?;
                    return Ok(());
                }
                Err(Error::Protocol {
                    class: ErrorClass::PROPERTY.to_raw() as u32,
                    code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
                })
            }
            // Clause 12.17 Table 12-20 lists Reliability O7; that footnote requires
            // writes to be supported while Out_Of_Service is TRUE. The property's
            // text specifies simulation/test writes to Present_Value and to
            // Reliability when present and capable of values beyond
            // NO_FAULT_DETECTED. In service the property is owned
            // by the algorithm, so a network write is refused here; the internal
            // evaluator route is `set_reliability_internal` with the complementary
            // guard, and Out_Of_Service saves/restores the evaluated value (handled
            // above the match).
            p if p == PropertyIdentifier::RELIABILITY => {
                if !self.out_of_service {
                    return Err(common::write_access_denied_error());
                }
                if let PropertyValue::Enumerated(raw) = value {
                    let v = Reliability::from_raw(raw);
                    if !common::is_reliability_value_valid(v) {
                        return Err(common::value_out_of_range_error());
                    }
                    self.reliability = v;
                    return Ok(());
                }
                Err(Error::Protocol {
                    class: ErrorClass::PROPERTY.to_raw() as u32,
                    code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
                })
            }
            p if p == PropertyIdentifier::DESCRIPTION => {
                if let PropertyValue::CharacterString(s) = value {
                    self.description = s;
                    return Ok(());
                }
                Err(Error::Protocol {
                    class: ErrorClass::PROPERTY.to_raw() as u32,
                    code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
                })
            }
            // Clause 12.17 / Clause 21 BACnetObjectPropertyReference: the
            // write value decodes via the shared arm helper — legacy local
            // List and framed network (context-tagged members) forms both
            // land strictly; see reference.rs.
            p if p == PropertyIdentifier::CONTROLLED_VARIABLE_REFERENCE => {
                self.controlled_variable_reference = crate::reference::decode_reference_write(
                    &value,
                    crate::reference::ReferenceFrame::Bare,
                )?;
                Ok(())
            }
            p if p == PropertyIdentifier::MANIPULATED_VARIABLE_REFERENCE => {
                self.manipulated_variable_reference = crate::reference::decode_reference_write(
                    &value,
                    crate::reference::ReferenceFrame::Bare,
                )?;
                Ok(())
            }
            // Setpoint_Reference is typed BACnetSetpointReference (Clause
            // 12.17): the reference may additionally arrive inside the
            // production's opening/closing tag [0] frame on the wire.
            p if p == PropertyIdentifier::SETPOINT_REFERENCE => {
                self.setpoint_reference = crate::reference::decode_reference_write(
                    &value,
                    crate::reference::ReferenceFrame::Setpoint,
                )?;
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
        metadata::for_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn supports_cov(&self) -> bool {
        true
    }

    fn cov_increment(&self) -> Option<f32> {
        Some(self.cov_increment)
    }

    fn set_present_value_internal(&mut self, value: PropertyValue) -> Result<(), Error> {
        // The complement of the network route: while Out_Of_Service is TRUE
        // a client's simulated output must not be overwritten by the algorithm.
        if self.out_of_service {
            return Err(common::write_access_denied_error());
        }
        self.apply_present_value(value)
    }

    fn set_reliability_internal(&mut self, reliability: Reliability) -> Result<(), Error> {
        // While Out_Of_Service is TRUE the client owns the simulated value;
        // an internal write would clobber the simulation (Clause 12.17
        // Out_Of_Service paragraph separates Reliability from algorithm output),
        // so it is refused until the object returns to service.
        if self.out_of_service {
            return Err(common::write_access_denied_error());
        }
        if !common::is_reliability_value_valid(reliability) {
            return Err(common::value_out_of_range_error());
        }
        self.reliability = reliability;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
