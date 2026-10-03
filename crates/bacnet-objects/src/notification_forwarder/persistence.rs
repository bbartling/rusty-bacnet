//! Keeping a forwarder's Subscribed_Recipients across a restart (Clause
//! 12.51.9).
//!
//! Like [`AuditLogPersistence`](crate::audit::AuditLogPersistence), the
//! storage belongs to the application: the forwarder calls it synchronously,
//! loading once when it is built and saving each time its list changes. Each
//! saved entry carries the whole minutes it had left at the save.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use bacnet_encoding::constructed::{
    decode_event_notification_subscription, encode_event_notification_subscription_list,
};
use bacnet_types::constructed::BACnetEventNotificationSubscription;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;

use crate::subscribed_recipients::MAX_SUBSCRIBED_RECIPIENTS;

/// Application-owned storage for one forwarder's Subscribed_Recipients.
pub trait SubscribedRecipientsPersistence: Send + Sync {
    /// The list last saved for `forwarder`, or `None` when nothing was saved.
    fn load(
        &self,
        forwarder: ObjectIdentifier,
    ) -> Result<Option<Vec<BACnetEventNotificationSubscription>>, Error>;

    /// Durably replace the list saved for `forwarder`. Each entry's Time
    /// Remaining is the whole minutes it has left now.
    fn save(
        &self,
        forwarder: ObjectIdentifier,
        subscriptions: &[BACnetEventNotificationSubscription],
    ) -> Result<(), Error>;
}

const MAGIC: &[u8; 8] = b"RBNFSR01";
const HEADER_LEN: usize = MAGIC.len() + 4;
/// A full list of the longest entries is 1,184 octets; anything much larger
/// is not a file this backend wrote.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// A file holding one forwarder's list, replaced whole on each save.
///
/// A save writes a sibling `.tmp` file, synchronizes it and renames it over
/// the old one, so a failed save leaves the previous list in place. The file
/// holds a magic tag, the forwarder's object identifier and the encoded list.
/// It does not coordinate between processes.
#[derive(Clone, Debug)]
pub struct FileSubscribedRecipientsPersistence {
    path: PathBuf,
}

impl FileSubscribedRecipientsPersistence {
    /// Keep the list in the file at `path`.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(Error::OutOfRange(
                "Subscribed_Recipients persistence path must not be empty".into(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// The file the list is kept in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn temporary_path(&self) -> PathBuf {
        let mut temporary = self.path.as_os_str().to_os_string();
        temporary.push(".tmp");
        PathBuf::from(temporary)
    }
}

fn corrupt(reason: &str) -> Error {
    Error::Encoding(format!("Subscribed_Recipients file {reason}"))
}

impl SubscribedRecipientsPersistence for FileSubscribedRecipientsPersistence {
    fn load(
        &self,
        forwarder: ObjectIdentifier,
    ) -> Result<Option<Vec<BACnetEventNotificationSubscription>>, Error> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(corrupt("is too large"));
        }
        if bytes.len() < HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC {
            return Err(corrupt("has no valid header"));
        }
        if bytes[MAGIC.len()..HEADER_LEN] != forwarder.encode() {
            return Err(corrupt("belongs to another object"));
        }
        let mut subscriptions = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < bytes.len() {
            if subscriptions.len() == MAX_SUBSCRIBED_RECIPIENTS {
                return Err(corrupt("holds more entries than the cap"));
            }
            let (subscription, next) = decode_event_notification_subscription(&bytes, offset)
                .map_err(|_| corrupt("holds an entry that does not decode"))?;
            subscriptions.push(subscription);
            offset = next;
        }
        Ok(Some(subscriptions))
    }

    fn save(
        &self,
        forwarder: ObjectIdentifier,
        subscriptions: &[BACnetEventNotificationSubscription],
    ) -> Result<(), Error> {
        let mut bytes = BytesMut::with_capacity(HEADER_LEN + 40 * subscriptions.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&forwarder.encode());
        encode_event_notification_subscription_list(&mut bytes, subscriptions);
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let temporary = self.temporary_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}
