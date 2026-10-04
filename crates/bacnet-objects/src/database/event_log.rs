//! The device's own event notifications into its Event Log objects
//! (Clause 12.27). The caller owns synchronization.

use bacnet_types::constructed::{
    BACnetDeviceObjectPropertyReference, BACnetEventLogRecord, EventLogDatum,
    EventNotificationRequest,
};
use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use tracing::{debug, warn};

use super::ObjectDatabase;
use crate::device_reference::decode_reference;

impl ObjectDatabase {
    /// Record an event notification this device generated in each of its
    /// Event Log objects, as a notification record stamped with the Device
    /// clock's local date and time.
    ///
    /// The server calls this for each notification it builds once the
    /// recipient lookup has read the Notification Class. Each log's own
    /// lifecycle decides what it keeps, as for a record the application adds
    /// through `add_record`: a disabled log ignores it, and a full log drops
    /// its oldest record or, with Stop_When_Full, stops and records that
    /// instead.
    ///
    /// No log takes a notification about an Event Log: one whose
    /// event-initiating object is an Event Log, or an Event Enrollment of this
    /// device monitoring a property of one. Logging it anywhere would add a
    /// record that changes what such reports watch, so a report could prompt
    /// the next without end, through the log it watches or crosswise through
    /// another log watched in turn.
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
        if self.reports_on_an_event_log(notification.event_object_identifier) {
            debug!(
                event_object = %notification.event_object_identifier,
                "Notification about an Event Log not logged"
            );
            return;
        }
        for oid in logs {
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

    /// Whether a notification about `event_object` reports on an Event Log of
    /// this device: `event_object` is an Event Log, or an Event Enrollment
    /// whose Object_Property_Reference names one here.
    fn reports_on_an_event_log(&self, event_object: ObjectIdentifier) -> bool {
        match event_object.object_type() {
            ObjectType::EVENT_LOG => true,
            ObjectType::EVENT_ENROLLMENT => self
                .get(&event_object)
                .and_then(|enrollment| {
                    enrollment
                        .read_property(PropertyIdentifier::OBJECT_PROPERTY_REFERENCE, None)
                        .ok()
                })
                .and_then(|value| {
                    decode_reference::<BACnetDeviceObjectPropertyReference>(&value).ok()
                })
                .is_some_and(|reference| {
                    reference.object_identifier.object_type() == ObjectType::EVENT_LOG
                        && self.local_device().is_local(reference.device_identifier)
                }),
            _ => false,
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
