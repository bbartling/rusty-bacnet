//! TrendLogMultiple (type 27, Clause 12.30).

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;

use bacnet_types::constructed::{BACnetDeviceObjectPropertyReference, BACnetLogMultipleRecord};
use bacnet_types::enums::{
    ErrorClass, ErrorCode, EventState, ObjectType, PropertyIdentifier, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};

use super::multiple_metadata;
use super::references::{self, MAX_LOG_DEVICE_OBJECT_PROPERTIES};
use crate::clock::ClockReader;
use crate::common::{self, read_property_list_property};
use crate::device_reference;
use crate::log_buffer::{
    log_buffer_read_denied, LogBufferRecords, LogRecordBuffer, LogRecordIdentity,
};
use crate::log_lifecycle::LogLifecycle;
use crate::traits::BACnetObject;

/// BACnet TrendLogMultiple object (type 27).
///
/// Multi-channel trending. Unlike TrendLog, which monitors a single property,
/// TrendLogMultiple monitors a list of device-object-property references and
/// logs one value per reference in each record. The database's trend poller
/// samples every reference at `log_interval` while Logging_Type is POLLED.
pub struct TrendLogMultipleObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    log_enable: bool,
    log_interval: u32,
    stop_when_full: bool,
    buffer_size: u32,
    log_buffer: LogRecordBuffer<BACnetLogMultipleRecord>,
    log_device_object_property: Vec<BACnetDeviceObjectPropertyReference>,
    logging_type: u32, // 0=polled, 1=cov, 2=triggered
    reliability: Reliability,
    clock: Option<Arc<dyn ClockReader>>,
}

impl TrendLogMultipleObject {
    /// Build a log with logging enabled that holds at most `buffer_size`
    /// records.
    pub fn new(instance: u32, name: impl Into<String>, buffer_size: u32) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::TREND_LOG_MULTIPLE, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            log_enable: true,
            log_interval: 0,
            stop_when_full: false,
            buffer_size,
            log_buffer: LogRecordBuffer::new(buffer_size),
            log_device_object_property: Vec::new(),
            logging_type: 0,
            reliability: Reliability::NO_FAULT_DETECTED,
            clock: None,
        })
    }

    /// Add a record to the log buffer.
    ///
    /// Success does not guarantee a resident ordinary record: disabled logging
    /// is ignored, zero-capacity logging may only count, and a stop-before-full
    /// transition records status instead. Missing/invalid status clocks fail
    /// atomically with DEVICE / OPERATIONAL_PROBLEM.
    pub fn add_record(&mut self, record: BACnetLogMultipleRecord) -> Result<(), Error> {
        self.lifecycle().try_add_ordinary(record).map(|_| ())
    }

    /// Append a reference to Log_DeviceObjectProperty as local configuration:
    /// the log buffer is left as it is.
    ///
    /// A reference may name another device; the poller then logs a failure
    /// in its slot of each record instead of reading it. A Device member that
    /// isn't a Device identifier fails with PROPERTY / VALUE_OUT_OF_RANGE, and
    /// a reference past [`MAX_LOG_DEVICE_OBJECT_PROPERTIES`] with RESOURCES /
    /// NO_SPACE_TO_WRITE_PROPERTY; either leaves the array unchanged.
    pub fn add_property_reference(
        &mut self,
        reference: BACnetDeviceObjectPropertyReference,
    ) -> Result<(), Error> {
        device_reference::check_device_member(reference.device_identifier)?;
        if self.log_device_object_property.len() >= MAX_LOG_DEVICE_OBJECT_PROPERTIES {
            return Err(references::no_space_error());
        }
        self.log_device_object_property.push(reference);
        Ok(())
    }

    /// A client's write of Log_DeviceObjectProperty (#1234).
    ///
    /// A whole write replaces the array, at any length up to
    /// [`MAX_LOG_DEVICE_OBJECT_PROPERTIES`]; an indexed write replaces one
    /// element. Writing index 0 resizes the array (Clause 12.1.5.1): a smaller
    /// Unsigned drops the trailing elements, a larger one appends empty
    /// elements, one past the cap is RESOURCES / NO_SPACE_TO_WRITE_PROPERTY and
    /// another datatype PROPERTY / INVALID_DATA_TYPE. Each written reference
    /// goes through [`references::check_written`], where an element naming
    /// instance 4194303 is an empty one. A new value purges the buffer,
    /// leaving a BUFFER_PURGED status record, which is the first of the two
    /// actions Clause 12.30.11 offers; without a valid clock the purge fails
    /// with DEVICE / OPERATIONAL_PROBLEM and nothing changes. Writing the value
    /// already held changes nothing.
    fn write_log_device_object_property(
        &mut self,
        array_index: Option<u32>,
        value: PropertyValue,
    ) -> Result<(), Error> {
        let mut candidate = self.log_device_object_property.clone();
        match array_index {
            None => {
                let written = device_reference::decode_property_references(&value)?;
                if written.len() > MAX_LOG_DEVICE_OBJECT_PROPERTIES {
                    return Err(references::no_space_error());
                }
                for reference in &written {
                    references::check_written(reference, true)?;
                }
                candidate = written;
            }
            Some(0) => {
                let PropertyValue::Unsigned(size) = value else {
                    return Err(common::invalid_data_type_error());
                };
                let size = usize::try_from(size)
                    .ok()
                    .filter(|size| *size <= MAX_LOG_DEVICE_OBJECT_PROPERTIES)
                    .ok_or_else(references::no_space_error)?;
                candidate.resize_with(size, references::empty_element);
            }
            Some(index) => {
                let slot = usize::try_from(index - 1)
                    .ok()
                    .and_then(|slot| candidate.get_mut(slot))
                    .ok_or_else(common::invalid_array_index_error)?;
                let reference = device_reference::decode_property_reference(&value)?;
                references::check_written(&reference, true)?;
                *slot = reference;
            }
        }
        if candidate != self.log_device_object_property {
            self.lifecycle().purge()?;
            self.log_device_object_property = candidate;
        }
        Ok(())
    }

    /// Get the current buffer contents.
    pub fn records(&self) -> &VecDeque<BACnetLogMultipleRecord> {
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

    /// Set the logging type (0=polled, 1=cov, 2=triggered).
    pub fn set_logging_type(&mut self, logging_type: u32) {
        self.logging_type = logging_type;
    }

    fn lifecycle(&mut self) -> LogLifecycle<'_, BACnetLogMultipleRecord> {
        LogLifecycle::new(
            &mut self.log_buffer,
            &mut self.log_enable,
            &mut self.stop_when_full,
            self.clock.as_ref(),
        )
    }
}

impl BACnetObject for TrendLogMultipleObject {
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
            p if p == PropertyIdentifier::OBJECT_TYPE => Ok(PropertyValue::Enumerated(
                ObjectType::TREND_LOG_MULTIPLE.to_raw(),
            )),
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
            // Clause 12.30.5 lets only IN_ALARM (from Event_State) and FAULT
            // (from Reliability) move on a Trend Log Multiple; OVERRIDDEN and
            // OUT_OF_SERVICE are always FALSE. Table 12-35 has no
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
            // ReadRange pages it through `log_buffer_internal`.
            p if p == PropertyIdentifier::LOG_BUFFER => Err(log_buffer_read_denied()),
            p if p == PropertyIdentifier::LOGGING_TYPE => {
                Ok(PropertyValue::Enumerated(self.logging_type))
            }
            // A BACnetARRAY: one Clause 21 encoding per element (#1234).
            p if p == PropertyIdentifier::LOG_DEVICE_OBJECT_PROPERTY => common::read_array(
                self.log_device_object_property
                    .iter()
                    .map(device_reference::property_reference_value)
                    .collect(),
                array_index,
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
        array_index: Option<u32>,
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
        if property == PropertyIdentifier::LOG_DEVICE_OBJECT_PROPERTY {
            return self.write_log_device_object_property(array_index, value);
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        Err(crate::common::unhandled_write_error(
            self.property_metadata().as_ref(),
            property,
            array_index,
        ))
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        multiple_metadata::for_object(self)
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

    fn log_buffer_internal(&self) -> Option<&dyn LogBufferRecords> {
        Some(&self.log_buffer)
    }

    fn add_trend_multiple_record(&mut self, record: BACnetLogMultipleRecord) -> Result<(), Error> {
        self.add_record(record)
    }
}
