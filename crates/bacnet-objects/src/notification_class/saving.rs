//! When a Notification Class saves its Recipient_List (Clause 12.21.8,
//! #1315).
//!
//! A class built with [`NotificationClass::with_persistence`] saves a written
//! Recipient_List before serving it, and refuses a write it cannot save with
//! DEVICE / OPERATIONAL_PROBLEM, keeping the old list. This is the
//! Notification Forwarder's scheme ([`crate::durable`]), shared with it
//! through `StagedSaves`: the bundled server stages the write, the save runs
//! on the class's writer thread while the database guard is dropped, and the
//! write then takes the saved list without saving again. A write that was
//! not staged queues its save and waits for it where it is.
//!
//! A staged write its request releases without making is dropped, and the
//! class at once queues a save of the list it serves, so storage goes back to
//! that list. Nothing but a write changes the list, so the class has no saves
//! of its own between writes: a staged write whose request vanished without
//! releasing it is dropped, and storage put back, by the next write that
//! stages once
//! [`STAGED_WRITE_LIFETIME`](crate::durable::STAGED_WRITE_LIFETIME) is over.
//!
//! A written list wins over the destinations the application configures:
//! once a write has set the list and it was saved, a rebuilt class serves the
//! saved list, and [`add_destination`](NotificationClass::add_destination)
//! checks a destination without adding it. The configured destinations are
//! never saved.

use std::sync::Arc;

use bacnet_types::constructed::BACnetDestination;
use bacnet_types::enums::{ErrorClass, ErrorCode, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use super::persistence::{NotificationClassPersistence, NotificationClassSnapshot};
use super::{recipient_list, NotificationClass, MAX_RECIPIENT_LIST_DESTINATIONS};
use crate::common;
use crate::durable::staged::StagedSaves;
use crate::durable::{DurableWrites, SaveWait, SaveWriter, StageStep};

/// A class's writer and the Recipient_List write staged on it.
pub(super) type Storage = StagedSaves<NotificationClassSnapshot, Vec<BACnetDestination>>;

impl NotificationClass {
    /// A Notification Class that keeps a written Recipient_List in
    /// `persistence`, starting from the list saved there for this object, if
    /// any. Its Notification_Class number defaults to the instance number,
    /// as with [`new`](Self::new).
    ///
    /// Fails when the saved list cannot be loaded, or holds what a write
    /// would refuse: more than [`MAX_RECIPIENT_LIST_DESTINATIONS`]
    /// destinations, or an address recipient whose MAC is too long.
    pub fn with_persistence(
        instance: u32,
        name: impl Into<String>,
        persistence: Arc<dyn NotificationClassPersistence>,
    ) -> Result<Self, Error> {
        let mut class = Self::new(instance, name)?;
        let oid = class.oid;
        if let Some(list) = persistence
            .load(oid)?
            .and_then(|saved| saved.recipient_list)
        {
            if list.len() > MAX_RECIPIENT_LIST_DESTINATIONS {
                return Err(recipient_list::no_space_error());
            }
            for destination in &list {
                recipient_list::check_added(destination)?;
            }
            class.recipient_list = list;
            class.recipient_list_written = true;
        }
        let writer = SaveWriter::new(
            format!("bacnet-nc-{instance}-save"),
            move |snapshot: &NotificationClassSnapshot| persistence.save(oid, snapshot),
            move |_, result| {
                if let Err(error) = result {
                    tracing::warn!(
                        class = %oid,
                        %error,
                        "Failed to save a Notification Class Recipient_List"
                    );
                }
            },
        );
        class.storage = Some(StagedSaves::new(writer));
        Ok(class)
    }

    /// Whether storage holds a Recipient_List a write set, now or before a
    /// restart. [`add_destination`](Self::add_destination) then leaves the
    /// list alone. Always false without persistence.
    pub fn recipient_list_saved(&self) -> bool {
        self.storage.is_some() && self.recipient_list_written
    }

    /// Block until the saves queued so far have run. Dropping the class
    /// waits for them too.
    pub fn wait_for_saves(&self) {
        if let Some(storage) = &self.storage {
            storage.wait_idle();
        }
    }

    /// What storage would hold with `next` as the Recipient_List, or with
    /// the served list when `next` is `None`.
    fn snapshot(&self, next: Option<&[BACnetDestination]>) -> NotificationClassSnapshot {
        NotificationClassSnapshot {
            recipient_list: match next {
                Some(list) => Some(list.to_vec()),
                None => self
                    .recipient_list_written
                    .then(|| self.recipient_list.clone()),
            },
        }
    }

    fn install(&mut self, list: Vec<BACnetDestination>) {
        self.recipient_list = list;
        self.recipient_list_written = true;
        self.list_writes = self.list_writes.wrapping_add(1);
    }

    /// Replace Recipient_List with a written list, saving it before the class
    /// serves it. A staged write takes the list already saved; any other
    /// saves now. A list that cannot be saved is refused with DEVICE /
    /// OPERATIONAL_PROBLEM and the old list stays.
    pub(super) fn write_recipient_list(&mut self, value: PropertyValue) -> Result<(), Error> {
        let refused =
            |_| common::protocol_error(ErrorClass::DEVICE, ErrorCode::OPERATIONAL_PROBLEM);
        let base = self.list_writes;
        if let Some(claimed) = self
            .with_storage(|storage| storage.claim(PropertyIdentifier::RECIPIENT_LIST, &value, base))
            .flatten()
        {
            self.install(claimed.map_err(refused)?);
            return Ok(());
        }
        let next = recipient_list::decode_write(value)?;
        let snapshot = self.storage.is_some().then(|| self.snapshot(Some(&next)));
        if let (Some(storage), Some(snapshot)) = (self.storage.as_mut(), snapshot) {
            storage.save_now(snapshot).map_err(refused)?;
        }
        self.install(next);
        Ok(())
    }

    /// Run `f` on storage; then, if `f` dropped a staged write, queue the
    /// save that puts storage back to the served list. `None` without
    /// persistence.
    fn with_storage<R>(&mut self, f: impl FnOnce(&mut Storage) -> R) -> Option<R> {
        let mut storage = self.storage.take()?;
        let result = f(&mut storage);
        storage.correct(|| self.snapshot(None));
        self.storage = Some(storage);
        Some(result)
    }
}

impl DurableWrites for NotificationClass {
    fn stage_write(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: &PropertyValue,
    ) -> StageStep {
        if property != PropertyIdentifier::RECIPIENT_LIST
            || array_index.is_some()
            || self.storage.is_none()
        {
            return StageStep::Skip;
        }
        if let Some(wait) = self.with_storage(|storage| storage.busy()).flatten() {
            return StageStep::Busy(wait);
        }
        let Ok(next) = recipient_list::decode_write(value.clone()) else {
            return StageStep::Skip;
        };
        let snapshot = self.snapshot(Some(&next));
        let base = self.list_writes;
        self.storage.as_mut().expect("checked above").stage(
            property,
            value.clone(),
            base,
            next,
            snapshot,
        )
    }

    fn release_staged_write(&mut self, staged: &SaveWait) {
        self.with_storage(|storage| storage.release(staged));
    }
}
