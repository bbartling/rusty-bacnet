//! Notification Forwarder object (type 51, Clause 12.51).
//!
//! A forwarder originates no events. It takes the event notifications this
//! device receives, and those its own objects address to the local Device,
//! and sends each one on to the destinations it holds: the configured
//! Recipient_List and the expiring Subscribed_Recipients. The server does the
//! sending; see [`forwarding_targets`] for which notifications a forwarder
//! takes and where it sends them.
//!
//! # Rows
//!
//! The object serves every required row of Table 12-58, plus Description and,
//! when the application configures one, Port_Filter. Over the network:
//!
//! - Recipient_List takes the same writes as a Notification Class's, capped
//!   at [`MAX_RECIPIENT_LIST_DESTINATIONS`] destinations.
//! - Subscribed_Recipients is a [`SubscribedRecipients`] store: entries run
//!   out after their Time Remaining and are edited by AddListElement and
//!   RemoveListElement.
//! - Process_Identifier_Filter takes an Unsigned32, or NULL to forward every
//!   process identifier; Local_Forwarding_Only and Out_Of_Service take a
//!   BOOLEAN.
//! - Port_Filter takes writes of its Enabled members only (Clause 12.51.11):
//!   the array keeps its size and Port_IDs.
//! - Reliability is always NO_FAULT_DETECTED and is not writable.
//!
//! # Restarts
//!
//! Clause 12.51.9 asks for Subscribed_Recipients to survive a restart. A
//! forwarder built with [`NotificationForwarderObject::with_persistence`]
//! saves the list, each entry with the minutes it has left, every time the
//! list changes, and restores it when built again. A restored entry counts
//! down from its saved minutes: no fewer than it had left when the device
//! stopped, and no more than its last subscription gave it. A forwarder built
//! with [`NotificationForwarderObject::new`] keeps the list in memory only.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use bacnet_types::constructed::{
    BACnetDestination, BACnetEventNotificationSubscription, BACnetPortPermission,
};
use bacnet_types::enums::{ObjectType, PropertyIdentifier, Reliability};
use bacnet_types::error::Error;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue, StatusFlags};
use bytes::BytesMut;

use crate::common::{self, read_common_properties};
use crate::notification_class::recipient_list;
use crate::subscribed_recipients::SubscribedRecipients;
use crate::traits::{BACnetObject, MonotonicClock};

mod metadata;
mod persistence;
mod port_filter;
mod selection;

pub use crate::notification_class::MAX_RECIPIENT_LIST_DESTINATIONS;
pub use persistence::{FileSubscribedRecipientsPersistence, SubscribedRecipientsPersistence};
pub use selection::{forwarding_targets, ForwardingInput, ForwardingTargets};

/// BACnet Notification Forwarder object (type 51). See the
/// [module documentation](self).
pub struct NotificationForwarderObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    status_flags: StatusFlags,
    reliability: Reliability,
    out_of_service: bool,
    recipient_list: Vec<BACnetDestination>,
    subscribed_recipients: SubscribedRecipients,
    process_identifier_filter: Option<u32>,
    local_forwarding_only: bool,
    port_filter: Option<Vec<BACnetPortPermission>>,
    persistence: Option<Arc<dyn SubscribedRecipientsPersistence>>,
}

impl NotificationForwarderObject {
    /// A forwarder with empty lists that forwards every process identifier
    /// for any device. Its Subscribed_Recipients is kept in memory only.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        Ok(Self {
            oid: ObjectIdentifier::new(ObjectType::NOTIFICATION_FORWARDER, instance)?,
            name: name.into(),
            description: String::new(),
            status_flags: StatusFlags::empty(),
            reliability: Reliability::NO_FAULT_DETECTED,
            out_of_service: false,
            recipient_list: Vec::new(),
            subscribed_recipients: SubscribedRecipients::new(),
            process_identifier_filter: None,
            local_forwarding_only: false,
            port_filter: None,
            persistence: None,
        })
    }

    /// A forwarder that keeps its Subscribed_Recipients in `persistence`,
    /// starting from the list saved there for this object, if any.
    ///
    /// Fails when the saved list cannot be loaded, or holds an entry the
    /// list would refuse (a Time Remaining of 0 or past a day, or more
    /// entries than the cap).
    pub fn with_persistence(
        instance: u32,
        name: impl Into<String>,
        persistence: Arc<dyn SubscribedRecipientsPersistence>,
    ) -> Result<Self, Error> {
        let mut forwarder = Self::new(instance, name)?;
        if let Some(saved) = persistence.load(forwarder.oid)? {
            forwarder.subscribed_recipients.write(framed(&saved)?)?;
        }
        forwarder.persistence = Some(persistence);
        Ok(forwarder)
    }

    /// Set the description string.
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = description.into();
    }

    /// The process identifier a notification must carry to be forwarded, or
    /// `None` (Process_Identifier_Filter NULL) to forward every one.
    pub fn process_identifier_filter(&self) -> Option<u32> {
        self.process_identifier_filter
    }

    /// Set Process_Identifier_Filter; `None` is NULL.
    pub fn set_process_identifier_filter(&mut self, filter: Option<u32>) {
        self.process_identifier_filter = filter;
    }

    /// Whether only notifications this device's own objects generate are
    /// forwarded.
    pub fn local_forwarding_only(&self) -> bool {
        self.local_forwarding_only
    }

    /// Set Local_Forwarding_Only.
    pub fn set_local_forwarding_only(&mut self, local_only: bool) {
        self.local_forwarding_only = local_only;
    }

    /// Add a destination to Recipient_List, with the checks and cap of a
    /// Notification Class's
    /// [`add_destination`](crate::notification_class::NotificationClass::add_destination).
    pub fn add_destination(&mut self, destination: BACnetDestination) -> Result<(), Error> {
        recipient_list::check_added(&destination)?;
        if self.recipient_list.len() >= MAX_RECIPIENT_LIST_DESTINATIONS {
            return Err(recipient_list::no_space_error());
        }
        self.recipient_list.push(destination);
        Ok(())
    }

    /// The Recipient_List destinations, in list order.
    pub fn recipient_list(&self) -> &[BACnetDestination] {
        &self.recipient_list
    }

    /// The live Subscribed_Recipients entries, each with the whole minutes it
    /// has left.
    pub fn subscriptions(&self) -> Vec<BACnetEventNotificationSubscription> {
        self.subscribed_recipients.subscriptions()
    }

    /// Serve Port_Filter with one element per network port, or `None` to
    /// leave the property out, as a device that does not route may
    /// (Clause 12.51.11). The server receives through one port, Port_ID 0.
    pub fn set_port_filter(&mut self, ports: Option<Vec<BACnetPortPermission>>) {
        self.port_filter = ports;
    }

    /// The Port_Filter elements, when the property is served.
    pub fn port_filter(&self) -> Option<&[BACnetPortPermission]> {
        self.port_filter.as_deref()
    }

    /// Save the list as it stands, when the forwarder has persistence.
    fn save(&self, store: &SubscribedRecipients) -> Result<(), Error> {
        match &self.persistence {
            Some(persistence) => persistence.save(self.oid, &store.subscriptions()),
            None => Ok(()),
        }
    }

    /// Replace Subscribed_Recipients with a written list, saving it before
    /// the forwarder serves it. A list that cannot be saved is refused with
    /// DEVICE / OPERATIONAL_PROBLEM and the old list stays.
    fn write_subscribed_recipients(&mut self, value: PropertyValue) -> Result<(), Error> {
        let mut next = self.subscribed_recipients.clone();
        next.write(value)?;
        self.save(&next).map_err(|_| {
            common::protocol_error(
                bacnet_types::enums::ErrorClass::DEVICE,
                bacnet_types::enums::ErrorCode::OPERATIONAL_PROBLEM,
            )
        })?;
        self.subscribed_recipients = next;
        Ok(())
    }

    /// After entries lapse, save what is left. A failed save keeps the
    /// earlier copy, whose entries a restart would restore with no more than
    /// their last subscribed time.
    fn after_lapse(&self, dropped: bool) -> bool {
        if dropped {
            let _ = self.save(&self.subscribed_recipients);
        }
        dropped
    }
}

/// A list of subscriptions in the framed form the store writes. Fails for a
/// recipient MAC past `BACnetAddress::MAX_MAC_LEN`, which a loaded list cannot
/// hold since its decoder refuses one.
fn framed(subscriptions: &[BACnetEventNotificationSubscription]) -> Result<PropertyValue, Error> {
    let mut buf = BytesMut::new();
    bacnet_encoding::constructed::encode_event_notification_subscription_list(
        &mut buf,
        subscriptions,
    )?;
    Ok(PropertyValue::ApplicationData(buf.to_vec()))
}

fn read_bool(value: &PropertyValue) -> Result<bool, Error> {
    match value {
        PropertyValue::Boolean(value) => Ok(*value),
        _ => Err(common::invalid_data_type_error()),
    }
}

impl BACnetObject for NotificationForwarderObject {
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
            PropertyIdentifier::OBJECT_TYPE => Ok(PropertyValue::Enumerated(
                ObjectType::NOTIFICATION_FORWARDER.to_raw(),
            )),
            PropertyIdentifier::RECIPIENT_LIST => {
                let mut buf = BytesMut::new();
                bacnet_encoding::constructed::encode_destination_list(
                    &mut buf,
                    &self.recipient_list,
                )?;
                Ok(PropertyValue::ApplicationData(buf.to_vec()))
            }
            PropertyIdentifier::SUBSCRIBED_RECIPIENTS => Ok(self.subscribed_recipients.read()),
            PropertyIdentifier::PROCESS_IDENTIFIER_FILTER => Ok(self
                .process_identifier_filter
                .map_or(PropertyValue::Null, |id| PropertyValue::Unsigned(id.into()))),
            PropertyIdentifier::LOCAL_FORWARDING_ONLY => {
                Ok(PropertyValue::Boolean(self.local_forwarding_only))
            }
            PropertyIdentifier::PORT_FILTER => match &self.port_filter {
                Some(ports) => port_filter::read(ports, array_index),
                None => Err(common::unknown_property_error()),
            },
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        let listed = matches!(
            property,
            PropertyIdentifier::RECIPIENT_LIST | PropertyIdentifier::SUBSCRIBED_RECIPIENTS
        );
        if listed && array_index.is_some() {
            return Err(common::property_is_not_an_array_error());
        }
        match property {
            PropertyIdentifier::RECIPIENT_LIST => {
                self.recipient_list = recipient_list::decode_write(value)?;
                return Ok(());
            }
            PropertyIdentifier::SUBSCRIBED_RECIPIENTS => {
                return self.write_subscribed_recipients(value);
            }
            PropertyIdentifier::PROCESS_IDENTIFIER_FILTER if array_index.is_none() => {
                self.process_identifier_filter = match value {
                    PropertyValue::Null => None,
                    PropertyValue::Unsigned(id) => {
                        Some(u32::try_from(id).map_err(|_| common::value_out_of_range_error())?)
                    }
                    _ => return Err(common::invalid_data_type_error()),
                };
                return Ok(());
            }
            PropertyIdentifier::LOCAL_FORWARDING_ONLY if array_index.is_none() => {
                self.local_forwarding_only = read_bool(&value)?;
                return Ok(());
            }
            PropertyIdentifier::PORT_FILTER => {
                if let Some(ports) = &mut self.port_filter {
                    return port_filter::write(ports, array_index, value);
                }
            }
            _ => {}
        }
        if array_index.is_none() {
            if let Some(result) =
                common::write_out_of_service(&mut self.out_of_service, property, &value)
            {
                return result;
            }
            if let Some(result) = common::write_description(&mut self.description, property, &value)
            {
                return result;
            }
        }
        Err(common::unhandled_write_error(
            self.property_metadata().as_ref(),
            property,
            array_index,
        ))
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        metadata::for_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn advance_time_internal(&mut self, elapsed: Duration) -> bool {
        let dropped = self.subscribed_recipients.advance_by(elapsed);
        self.after_lapse(dropped)
    }

    fn bind_monotonic_clock_internal(&mut self, clock: Option<Arc<MonotonicClock>>) {
        self.subscribed_recipients.bind_monotonic_clock(clock);
    }

    fn advance_monotonic_time_internal(&mut self, now: Duration) -> bool {
        let dropped = self.subscribed_recipients.advance_to(now);
        self.after_lapse(dropped)
    }

    fn next_monotonic_deadline_internal(&self) -> Option<Duration> {
        self.subscribed_recipients.next_deadline()
    }
}

#[cfg(test)]
mod tests;
