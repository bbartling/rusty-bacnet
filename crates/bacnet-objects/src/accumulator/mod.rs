//! Accumulator (type 23) and Pulse Converter (type 24) objects.
//!
//! Per ASHRAE 135-2020 §12.61 Table 12-79 (Accumulator) and §12.23 Table 12-27 (PulseConverter).

use bacnet_types::constructed::{BACnetPrescale, BACnetScale};
use bacnet_types::enums::{EventState, ObjectType, PropertyIdentifier, Reliability};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use std::borrow::Cow;

use crate::common::{self, read_common_properties};
use crate::traits::BACnetObject;

mod metadata;
mod pulse_converter;

pub use pulse_converter::PulseConverterObject;

// ---------------------------------------------------------------------------
// AccumulatorObject (type 23)
// ---------------------------------------------------------------------------

/// BACnet Accumulator object — tracks a pulse count with scaling.
pub struct AccumulatorObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    present_value: u64,
    max_pres_value: u64,
    scale: BACnetScale,
    prescale: Option<BACnetPrescale>,
    pulse_rate: f32,
    units: u32,
    limit_monitoring_interval: u32,
    status_flags: StatusFlags,
    event_state: EventState,
    out_of_service: bool,
    reliability: Reliability,
    value_before_change: u64,
    value_set: u64,
}

impl AccumulatorObject {
    /// Create a new Accumulator object with default values.
    pub fn new(instance: u32, name: impl Into<String>, units: u32) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCUMULATOR, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: 0,
            max_pres_value: u64::MAX,
            scale: BACnetScale::FloatScale(1.0),
            prescale: None,
            pulse_rate: 0.0,
            units,
            limit_monitoring_interval: 0,
            status_flags: StatusFlags::empty(),
            event_state: EventState::NORMAL,
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            value_before_change: 0,
            value_set: 0,
        })
    }

    /// Set the present value (application use).
    pub fn set_present_value(&mut self, value: u64) {
        self.present_value = value;
    }

    /// Set the description string.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Set the scale.
    pub fn set_scale(&mut self, scale: BACnetScale) {
        self.scale = scale;
    }

    /// Set the prescale.
    pub fn set_prescale(&mut self, prescale: BACnetPrescale) {
        self.prescale = Some(prescale);
    }
}

impl BACnetObject for AccumulatorObject {
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
                Ok(PropertyValue::Enumerated(ObjectType::ACCUMULATOR.to_raw()))
            }
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Unsigned(self.present_value))
            }
            p if p == PropertyIdentifier::MAX_PRES_VALUE => {
                Ok(PropertyValue::Unsigned(self.max_pres_value))
            }
            p if p == PropertyIdentifier::SCALE => match &self.scale {
                BACnetScale::FloatScale(v) => {
                    Ok(PropertyValue::List(vec![PropertyValue::Real(*v)]))
                }
                BACnetScale::IntegerScale(v) => {
                    Ok(PropertyValue::List(vec![PropertyValue::Signed(*v)]))
                }
            },
            p if p == PropertyIdentifier::PRESCALE => match &self.prescale {
                Some(ps) => Ok(PropertyValue::List(vec![
                    PropertyValue::Unsigned(ps.multiplier as u64),
                    PropertyValue::Unsigned(ps.modulo_divide as u64),
                ])),
                None => Ok(PropertyValue::Null),
            },
            p if p == PropertyIdentifier::PULSE_RATE => Ok(PropertyValue::Real(self.pulse_rate)),
            p if p == PropertyIdentifier::UNITS => Ok(PropertyValue::Enumerated(self.units)),
            p if p == PropertyIdentifier::LIMIT_MONITORING_INTERVAL => Ok(PropertyValue::Unsigned(
                self.limit_monitoring_interval as u64,
            )),
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            p if p == PropertyIdentifier::VALUE_BEFORE_CHANGE => {
                Ok(PropertyValue::Unsigned(self.value_before_change))
            }
            p if p == PropertyIdentifier::VALUE_SET => Ok(PropertyValue::Unsigned(self.value_set)),
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
        // Present value is read-only from the network
        if property == PropertyIdentifier::PRESENT_VALUE {
            return Err(common::write_access_denied_error());
        }
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::MAX_PRES_VALUE => {
                if let PropertyValue::Unsigned(v) = value {
                    self.max_pres_value = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::PULSE_RATE => {
                if let PropertyValue::Real(v) = value {
                    common::reject_non_finite(v)?;
                    self.pulse_rate = v;
                    Ok(())
                } else {
                    Err(common::invalid_data_type_error())
                }
            }
            p if p == PropertyIdentifier::LIMIT_MONITORING_INTERVAL => {
                if let PropertyValue::Unsigned(v) = value {
                    self.limit_monitoring_interval = common::u64_to_u32(v)?;
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
        metadata::for_accumulator_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn supports_cov(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_types::constructed::BACnetPrescale;

    // --- AccumulatorObject ---

    #[test]
    fn accumulator_create_and_read_defaults() {
        let acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        assert_eq!(acc.object_name(), "ACC-1");
        assert_eq!(
            acc.read_property(PropertyIdentifier::PRESENT_VALUE, None)
                .unwrap(),
            PropertyValue::Unsigned(0)
        );
        assert_eq!(
            acc.read_property(PropertyIdentifier::UNITS, None).unwrap(),
            PropertyValue::Enumerated(95)
        );
    }

    #[test]
    fn accumulator_read_present_value() {
        let mut acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        acc.set_present_value(42);
        assert_eq!(
            acc.read_property(PropertyIdentifier::PRESENT_VALUE, None)
                .unwrap(),
            PropertyValue::Unsigned(42)
        );
    }

    #[test]
    fn accumulator_present_value_read_only_from_network() {
        let mut acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        let result = acc.write_property(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Unsigned(10),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn accumulator_read_scale_float() {
        let acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        let val = acc.read_property(PropertyIdentifier::SCALE, None).unwrap();
        assert_eq!(val, PropertyValue::List(vec![PropertyValue::Real(1.0)]));
    }

    #[test]
    fn accumulator_read_scale_integer() {
        let mut acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        acc.set_scale(BACnetScale::IntegerScale(10));
        let val = acc.read_property(PropertyIdentifier::SCALE, None).unwrap();
        assert_eq!(val, PropertyValue::List(vec![PropertyValue::Signed(10)]));
    }

    #[test]
    fn accumulator_read_prescale_none() {
        let acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        let val = acc
            .read_property(PropertyIdentifier::PRESCALE, None)
            .unwrap();
        assert_eq!(val, PropertyValue::Null);
    }

    #[test]
    fn accumulator_read_prescale_set() {
        let mut acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        acc.set_prescale(BACnetPrescale {
            multiplier: 5,
            modulo_divide: 100,
        });
        let val = acc
            .read_property(PropertyIdentifier::PRESCALE, None)
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::List(vec![
                PropertyValue::Unsigned(5),
                PropertyValue::Unsigned(100),
            ])
        );
    }

    #[test]
    fn accumulator_object_type() {
        let acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        let val = acc
            .read_property(PropertyIdentifier::OBJECT_TYPE, None)
            .unwrap();
        assert_eq!(
            val,
            PropertyValue::Enumerated(ObjectType::ACCUMULATOR.to_raw())
        );
    }

    #[test]
    fn accumulator_property_list() {
        let acc = AccumulatorObject::new(1, "ACC-1", 95).unwrap();
        let list = acc.property_list();
        assert!(list.contains(&PropertyIdentifier::PRESENT_VALUE));
        assert!(list.contains(&PropertyIdentifier::SCALE));
        assert!(list.contains(&PropertyIdentifier::PRESCALE));
        assert!(list.contains(&PropertyIdentifier::MAX_PRES_VALUE));
        assert!(list.contains(&PropertyIdentifier::PULSE_RATE));
    }
}
