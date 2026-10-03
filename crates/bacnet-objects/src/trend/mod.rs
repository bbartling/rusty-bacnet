//! TrendLog (type 20) and TrendLogMultiple (type 27) objects per ASHRAE 135-2020.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;

use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, BACnetLogRecord};
use bacnet_types::enums::{
    ErrorClass, ErrorCode, EventState, ObjectType, PropertyIdentifier, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};

use crate::clock::ClockReader;
use crate::common::{self, read_property_list_property};
use crate::log_buffer::{LogRecordBuffer, LogRecordIdentity, LogRecordProfile};
use crate::log_lifecycle::LogLifecycle;
use crate::traits::BACnetObject;

mod metadata;
mod multiple;
mod multiple_metadata;

pub use multiple::TrendLogMultipleObject;

/// BACnet TrendLog object.
///
/// Ring buffer of timestamped property values. The application calls
/// `add_record()` to log values at `log_interval` intervals.
pub struct TrendLogObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    log_enable: bool,
    log_interval: u32,
    stop_when_full: bool,
    buffer_size: u32,
    log_buffer: LogRecordBuffer,
    reliability: Reliability,
    log_device_object_property: Option<BACnetDeviceObjectPropertyReference>,
    logging_type: u32, // 0=polled, 1=cov, 2=triggered
    clock: Option<Arc<dyn ClockReader>>,
}

impl TrendLogObject {
    /// Create a new Trend Log object with logging enabled; `buffer_size` is the record capacity.
    pub fn new(instance: u32, name: impl Into<String>, buffer_size: u32) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::TREND_LOG, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            log_enable: true,
            log_interval: 0,
            stop_when_full: false,
            buffer_size,
            log_buffer: LogRecordBuffer::new(buffer_size),
            reliability: Reliability::NO_FAULT_DETECTED,
            log_device_object_property: None,
            logging_type: 0,
            clock: None,
        })
    }

    /// Add a BACnetLogRecord to the trend log buffer.
    ///
    /// Success does not guarantee a resident ordinary record: disabled logging
    /// is ignored, zero-capacity logging may only count, and a stop-before-full
    /// transition records status instead. Missing/invalid status clocks fail
    /// atomically with DEVICE / OPERATIONAL_PROBLEM.
    pub fn add_record(&mut self, record: BACnetLogRecord) -> Result<(), Error> {
        self.lifecycle().try_add_ordinary(record).map(|_| ())
    }

    /// Get the current buffer contents.
    pub fn records(&self) -> &VecDeque<BACnetLogRecord> {
        self.log_buffer.records()
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.log_buffer.clear();
    }

    /// Set the description string.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Set the log device object property reference.
    pub fn set_log_device_object_property(
        &mut self,
        reference: Option<BACnetDeviceObjectPropertyReference>,
    ) {
        self.log_device_object_property = reference;
    }

    /// Set the logging type (0=polled, 1=cov, 2=triggered).
    pub fn set_logging_type(&mut self, logging_type: u32) {
        self.logging_type = logging_type;
    }

    fn lifecycle(&mut self) -> LogLifecycle<'_, BACnetLogRecord> {
        LogLifecycle::new(
            &mut self.log_buffer,
            &mut self.log_enable,
            &mut self.stop_when_full,
            self.clock.as_ref(),
        )
    }
}

impl BACnetObject for TrendLogObject {
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
                Ok(PropertyValue::Enumerated(ObjectType::TREND_LOG.to_raw()))
            }
            p if p == PropertyIdentifier::LOG_ENABLE => Ok(PropertyValue::Boolean(self.log_enable)),
            p if p == PropertyIdentifier::LOG_INTERVAL => {
                Ok(PropertyValue::Unsigned(self.log_interval as u64))
            }
            p if p == PropertyIdentifier::STOP_WHEN_FULL => {
                Ok(PropertyValue::Boolean(self.stop_when_full))
            }
            p if p == PropertyIdentifier::BUFFER_SIZE => {
                Ok(PropertyValue::Unsigned(self.buffer_size as u64))
            }
            p if p == PropertyIdentifier::RECORD_COUNT => {
                Ok(PropertyValue::Unsigned(self.records().len() as u64))
            }
            p if p == PropertyIdentifier::TOTAL_RECORD_COUNT => Ok(PropertyValue::Unsigned(
                self.log_buffer.total_record_count() as u64,
            )),
            // Clause 12.25.30 lets only IN_ALARM (from Event_State) and FAULT
            // (from Reliability) move on a Trend Log; OVERRIDDEN and
            // OUT_OF_SERVICE are always FALSE. Table 12-29 has no
            // Out_Of_Service property (#985).
            p if p == PropertyIdentifier::STATUS_FLAGS => Ok(common::compute_status_flags(
                StatusFlags::empty(),
                self.reliability,
                false,
                EventState::NORMAL,
            )),
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(EventState::NORMAL.to_raw()))
            }
            p if p == PropertyIdentifier::RELIABILITY => {
                Ok(PropertyValue::Enumerated(self.reliability.to_raw()))
            }
            p if p == PropertyIdentifier::LOG_BUFFER => {
                Ok(self.log_buffer.project(LogRecordProfile::Trend))
            }
            p if p == PropertyIdentifier::LOGGING_TYPE => {
                Ok(PropertyValue::Enumerated(self.logging_type))
            }
            p if p == PropertyIdentifier::LOG_DEVICE_OBJECT_PROPERTY => Ok(self
                .log_device_object_property
                .as_ref()
                .map_or(PropertyValue::Null, reference_value)),
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
        if property == PropertyIdentifier::LOG_ENABLE {
            if let PropertyValue::Boolean(v) = value {
                return self.lifecycle().write_enable(v);
            }
            return Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
            });
        }
        if property == PropertyIdentifier::LOG_INTERVAL {
            if let PropertyValue::Unsigned(v) = value {
                self.log_interval = common::u64_to_u32(v)?;
                return Ok(());
            }
            return Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
            });
        }
        if property == PropertyIdentifier::STOP_WHEN_FULL {
            if let PropertyValue::Boolean(v) = value {
                return self.lifecycle().write_stop_when_full(v);
            }
            return Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
            });
        }
        if property == PropertyIdentifier::RECORD_COUNT {
            if let PropertyValue::Unsigned(0) = value {
                return self.lifecycle().purge();
            }
            return Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::INVALID_DATA_TYPE.to_raw() as u32,
            });
        }
        // Clause 12.25 Table 12-29 lists Reliability as plain O with no
        // writability footnote, and unlike the intrinsic-reporting objects the
        // Trend Log Reliability_Evaluation_Inhibit paragraph requires
        // NO_FAULT_DETECTED while evaluation is inhibited, without an exception
        // for a client-supplied Reliability value while Out_Of_Service is TRUE.
        // Nothing in Clause 12.25 grants a
        // network client this property: the log owns it (logging status and
        // fault indication), so every write is refused.
        if property == PropertyIdentifier::RELIABILITY {
            return Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::WRITE_ACCESS_DENIED.to_raw() as u32,
            });
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

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn bind_clock_internal(&mut self, clock: Option<Arc<dyn ClockReader>>) {
        self.clock = clock;
    }

    fn log_record_identities_internal(&self) -> Option<Vec<LogRecordIdentity>> {
        Some(self.log_buffer.identities())
    }

    fn add_trend_record(&mut self, record: BACnetLogRecord) -> Result<(), Error> {
        self.add_record(record)
    }
}

/// One Log_DeviceObjectProperty reference as a read projects it: the object,
/// property, array index and device, with Null for an absent member.
fn reference_value(reference: &BACnetDeviceObjectPropertyReference) -> PropertyValue {
    PropertyValue::List(vec![
        PropertyValue::ObjectIdentifier(reference.object_identifier),
        PropertyValue::Unsigned(reference.property_identifier as u64),
        reference
            .property_array_index
            .map_or(PropertyValue::Null, |index| {
                PropertyValue::Unsigned(index as u64)
            }),
        reference
            .device_identifier
            .map_or(PropertyValue::Null, PropertyValue::ObjectIdentifier),
    ])
}

#[cfg(test)]
mod log_record_tests;

#[cfg(test)]
mod tests;
