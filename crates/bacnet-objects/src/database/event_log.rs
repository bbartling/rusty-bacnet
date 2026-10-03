//! The device's own event notifications into its Event Log objects
//! (Clause 12.27). The caller owns synchronization.

use bacnet_types::constructed::{BACnetEventLogRecord, EventLogDatum, EventNotificationRequest};
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use tracing::{debug, warn};

use super::ObjectDatabase;
use crate::device_reference::decode_property_reference;

impl ObjectDatabase {
    /// Record an event notification this device generated in each of its
    /// Event Log objects, as a notification record stamped with the Device
    /// clock's local date and time.
    ///
    /// The server calls this for every notification it builds. Each log's own
    /// lifecycle decides what it keeps, as for a record the application adds
    /// through `add_record`: a disabled log ignores it, and a full log drops
    /// its oldest record or, with Stop_When_Full, stops and records that
    /// instead.
    ///
    /// A log never takes a notification about itself: one whose
    /// event-initiating object is the log, or an Event Enrollment of this
    /// device that monitors one of the log's properties. Each such
    /// notification would add a record, and the record would change what is
    /// reported on, so a log taking them could prompt notifications about
    /// itself without end. The other logs still take them.
    ///
    /// Without a valid Device clock no record can carry its timestamp, so
    /// nothing is logged. A log that refuses the record keeps its state; the
    /// refusal goes to the trace log and the other logs still take it. The
    /// notification is stored as given, Process Identifier included: Clause
    /// 12.27 leaves that parameter of a locally generated record to the device.
    pub fn log_event_notification(&mut self, notification: &EventNotificationRequest) {
        let logs = self.find_by_type(ObjectType::EVENT_LOG);
        if logs.is_empty() {
            return;
        }
        let Some(frame) = self
            .clock_frame()
            .filter(|frame| frame.is_valid_actual_datetime())
        else {
            debug!(
                event_object = %notification.event_object_identifier,
                "No valid Device clock; event notification not logged"
            );
            return;
        };
        let reported_log = self.reported_log(notification.event_object_identifier);
        for oid in logs {
            if Some(oid) == reported_log {
                continue;
            }
            let Some(log) = self.get_mut(&oid) else {
                continue;
            };
            let record = BACnetEventLogRecord {
                date: frame.local_date,
                time: frame.local_time,
                log_datum: EventLogDatum::Notification(notification.clone()),
            };
            match log.add_event_log_record(record) {
                Ok(()) => {}
                Err(error) if is_unsupported(&error) => {
                    debug!(log = %oid, "Event Log object takes no records");
                }
                Err(error) => {
                    warn!(log = %oid, %error, "Event Log refused an event notification record");
                }
            }
        }
    }

    /// The Event Log a notification about `event_object` reports on: the
    /// object itself when it is an Event Log, or the local Event Log an Event
    /// Enrollment monitors.
    fn reported_log(&self, event_object: ObjectIdentifier) -> Option<ObjectIdentifier> {
        match event_object.object_type() {
            ObjectType::EVENT_LOG => Some(event_object),
            ObjectType::EVENT_ENROLLMENT => {
                let value = self
                    .get(&event_object)?
                    .read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
                    .ok()?;
                let reference = decode_property_reference(&value).ok()?;
                (reference.object_identifier.object_type() == ObjectType::EVENT_LOG
                    && self.local_device().is_local(reference.device_identifier))
                .then_some(reference.object_identifier)
            }
            _ => None,
        }
    }
}

/// The trait default's answer: an object of type Event Log that has no
/// record insertion.
fn is_unsupported(error: &Error) -> bool {
    matches!(error, Error::Protocol { class, code }
        if *class == ErrorClass::OBJECT.to_raw() as u32
            && *code == ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.to_raw() as u32)
}

#[cfg(test)]
#[path = "event_log_tests.rs"]
mod tests;
