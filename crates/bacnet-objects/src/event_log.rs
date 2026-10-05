//! EventLog (type 25) object per ASHRAE 135-2020 Clause 12.27.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;

use bacnet_types::constructed::BACnetEventLogRecord;
use bacnet_types::enums::{EventState, ObjectType, PropertyIdentifier, Reliability};
use bacnet_types::error::Error;
use bacnet_types::primitives::{Date, ObjectIdentifier, PropertyValue, StatusFlags, Time};

use crate::clock::ClockReader;
use crate::common::{self, read_common_properties};
use crate::log_buffer::{
    log_buffer_read_denied, LogBufferRecords, LogRecordBuffer, LogRecordIdentity,
};
use crate::log_lifecycle::LogLifecycle;
use crate::log_window::LogWindow;
use crate::traits::BACnetObject;

mod metadata;

/// BACnet EventLog object.
///
/// Ring buffer of timestamped event log records. A server running the
/// database logs the event notifications the device builds into its Event
/// Logs ([`ObjectDatabase::log_event_notification`]); the application calls
/// `add_record()` for anything else, such as a clock change or a notification
/// it received. The log adds its own status records. Records are kept only
/// while Enable is TRUE and the local time lies between Start_Time and
/// Stop_Time; the database's trend poller looks at that window on every
/// pass, so an opening or closing is recorded even when no record arrives.
///
/// [`ObjectDatabase::log_event_notification`]: crate::database::ObjectDatabase::log_event_notification
pub struct EventLogObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    log_enable: bool,
    stop_when_full: bool,
    buffer_size: u32,
    log_buffer: LogRecordBuffer<BACnetEventLogRecord>,
    status_flags: StatusFlags,
    event_state: EventState,
    reliability: Reliability,
    window: LogWindow,
    clock: Option<Arc<dyn ClockReader>>,
}

impl EventLogObject {
    /// Create a new EventLog object.
    pub fn new(instance: u32, name: impl Into<String>, buffer_size: u32) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::EVENT_LOG, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            log_enable: true,
            stop_when_full: false,
            buffer_size,
            log_buffer: LogRecordBuffer::new(buffer_size),
            status_flags: StatusFlags::empty(),
            event_state: EventState::NORMAL,
            reliability: Reliability::NO_FAULT_DETECTED,
            window: LogWindow::default(),
            clock: None,
        })
    }

    /// Add a record to the event log buffer.
    ///
    /// The record is kept as given; ReadRange serves its encoding, which for
    /// an ACK_NOTIFICATION leaves out ack-required, from-state and event
    /// values (see `EventLogDatum::Notification`).
    ///
    /// Success does not guarantee a resident ordinary record: disabled logging
    /// and a record outside the Start_Time / Stop_Time window are ignored,
    /// zero-capacity logging may only count, and a stop-before-full
    /// transition records status instead. Missing/invalid status clocks fail
    /// atomically with DEVICE / OPERATIONAL_PROBLEM.
    pub fn add_record(&mut self, record: BACnetEventLogRecord) -> Result<(), Error> {
        self.lifecycle().try_add_ordinary(record).map(|_| ())
    }

    /// Get the current buffer contents.
    pub fn records(&self) -> &VecDeque<BACnetEventLogRecord> {
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

    /// Set Start_Time, the local date and time from which records are kept,
    /// as local configuration: nothing is recorded for the change itself,
    /// but the log notes at once where the window stands, so a client's
    /// write that then opens or shuts it is recorded. Every field
    /// unspecified leaves the start open. Any other value has to name an
    /// actual date and time, or it is PROPERTY / VALUE_OUT_OF_RANGE: the
    /// weekday may stay unspecified, and unspecified seconds or hundredths
    /// count as zero.
    pub fn set_start_time(&mut self, date: Date, time: Time) -> Result<(), Error> {
        self.lifecycle()
            .configure_window(PropertyIdentifier::START_TIME, (date, time))
    }

    /// Set Stop_Time, the local date and time from which records are no
    /// longer kept, under the same rules as
    /// [`set_start_time`](Self::set_start_time).
    pub fn set_stop_time(&mut self, date: Date, time: Time) -> Result<(), Error> {
        self.lifecycle()
            .configure_window(PropertyIdentifier::STOP_TIME, (date, time))
    }

    fn lifecycle(&mut self) -> LogLifecycle<'_, BACnetEventLogRecord> {
        LogLifecycle::new(
            &mut self.log_buffer,
            &mut self.log_enable,
            &mut self.stop_when_full,
            self.clock.as_ref(),
            &mut self.window,
        )
    }
}

impl BACnetObject for EventLogObject {
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
        // Table 12-31 has neither Out_Of_Service nor Log_Interval (#1064), and
        // Clause 12.27 holds the OUT_OF_SERVICE flag FALSE.
        if let Some(result) =
            read_common_properties!(self, property, array_index, no_out_of_service)
        {
            return result;
        }
        if let Some(value) = self.window.read(property) {
            return Ok(value);
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::EVENT_LOG.to_raw()))
            }
            p if p == PropertyIdentifier::LOG_ENABLE => Ok(PropertyValue::Boolean(self.log_enable)),
            p if p == PropertyIdentifier::STOP_WHEN_FULL => {
                Ok(PropertyValue::Boolean(self.stop_when_full))
            }
            p if p == PropertyIdentifier::BUFFER_SIZE => {
                Ok(PropertyValue::Unsigned(self.buffer_size as u64))
            }
            // ReadRange pages it through `log_buffer_internal`.
            p if p == PropertyIdentifier::LOG_BUFFER => Err(log_buffer_read_denied()),
            p if p == PropertyIdentifier::RECORD_COUNT => {
                Ok(PropertyValue::Unsigned(self.records().len() as u64))
            }
            p if p == PropertyIdentifier::TOTAL_RECORD_COUNT => Ok(PropertyValue::Unsigned(
                self.log_buffer.total_record_count() as u64,
            )),
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
        if property == PropertyIdentifier::LOG_ENABLE {
            if let PropertyValue::Boolean(v) = value {
                return self.lifecycle().write_enable(v);
            }
            return Err(common::invalid_data_type_error());
        }
        if let Some(result) = self.window.write(property, &value) {
            // A change that opens or closes the window is recorded at once.
            result?;
            self.lifecycle().refresh_window();
            return Ok(());
        }
        if property == PropertyIdentifier::STOP_WHEN_FULL {
            if let PropertyValue::Boolean(v) = value {
                return self.lifecycle().write_stop_when_full(v);
            }
            return Err(common::invalid_data_type_error());
        }
        if property == PropertyIdentifier::RECORD_COUNT {
            if let PropertyValue::Unsigned(0) = value {
                return self.lifecycle().purge();
            }
            return Err(common::invalid_data_type_error());
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

    fn log_buffer_internal(&self) -> Option<&dyn LogBufferRecords> {
        Some(&self.log_buffer)
    }

    fn add_event_log_record(&mut self, record: BACnetEventLogRecord) -> Result<(), Error> {
        self.add_record(record)
    }

    fn refresh_log_window_internal(&mut self) -> bool {
        self.lifecycle().refresh_window()
    }
}

#[cfg(test)]
mod tests;
