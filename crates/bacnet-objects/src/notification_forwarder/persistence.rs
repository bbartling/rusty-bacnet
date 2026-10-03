//! Keeping a forwarder's Recipient_List and Subscribed_Recipients across a
//! restart (Clauses 12.51.8 and 12.51.9).
//!
//! Like [`AuditLogPersistence`](crate::audit::AuditLogPersistence), the
//! storage belongs to the application. The forwarder loads it once, when it is
//! built, and saves both lists whenever either changes. Saves run on the
//! forwarder's own writer thread. The bundled server waits for them with the
//! database guard dropped; a write nobody staged waits where it is
//! ([`crate::durable`] lists those paths). Each saved Subscribed_Recipients
//! entry carries the whole minutes it had left at the save.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use bacnet_encoding::constructed::{
    decode_destination, decode_event_notification_subscription, encode_destination_list,
    encode_event_notification_subscription_list,
};
use bacnet_types::constructed::{BACnetDestination, BACnetEventNotificationSubscription};
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;

use super::MAX_RECIPIENT_LIST_DESTINATIONS;
use crate::durable::sync_parent_dir;
use crate::subscribed_recipients::MAX_SUBSCRIBED_RECIPIENTS;

/// What a forwarder keeps across a restart: both of its lists.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ForwarderSnapshot {
    /// Recipient_List, in list order, once a write has set it. `None` until
    /// then: the destinations the application configures apply at each
    /// start.
    pub recipient_list: Option<Vec<BACnetDestination>>,
    /// The live Subscribed_Recipients entries, in list order, each with the
    /// whole minutes it had left when saved.
    pub subscribed_recipients: Vec<BACnetEventNotificationSubscription>,
}

/// Application-owned storage for one Notification Forwarder's lists.
///
/// The forwarder calls it from its writer thread, one call at a time.
pub trait NotificationForwarderPersistence: Send + Sync {
    /// The lists last saved for `forwarder`, or `None` when nothing was
    /// saved.
    fn load(&self, forwarder: ObjectIdentifier) -> Result<Option<ForwarderSnapshot>, Error>;

    /// Durably replace what is saved for `forwarder` with `snapshot`.
    fn save(&self, forwarder: ObjectIdentifier, snapshot: &ForwarderSnapshot) -> Result<(), Error>;
}

const MAGIC: &[u8; 8] = b"RBNFWD01";
const OID_AT: usize = MAGIC.len();
/// One octet: 1 when the file holds a Recipient_List, 0 when not.
const WRITTEN_AT: usize = OID_AT + 4;
const LENGTH_AT: usize = WRITTEN_AT + 1;
/// The magic tag, the object identifier, the Recipient_List's presence and
/// its length.
const HEADER_LEN: usize = LENGTH_AT + 4;
/// A full Recipient_List of the longest destinations is 1,504 octets and a
/// full Subscribed_Recipients 1,184; anything much larger is not a file this
/// backend wrote.
pub(super) const MAX_FILE_BYTES: u64 = 64 * 1024;

/// A file holding one forwarder's lists, replaced whole on each save.
///
/// A save writes a sibling `.tmp` file, synchronizes it, renames it over the
/// old one and then synchronizes the directory, so a failed save leaves the
/// previous lists in place and a completed one survives a power loss. Once
/// the rename succeeds the save has landed: a directory sync that fails is
/// logged, not returned. (On Windows the directory is not synchronized: see
/// the [`durable`](crate::durable) module.) The file holds a magic tag, the
/// forwarder's object identifier, whether a Recipient_List follows, the
/// encoded Recipient_List with its length, and the encoded
/// Subscribed_Recipients. It does not coordinate between processes.
#[derive(Clone, Debug)]
pub struct FileNotificationForwarderPersistence {
    path: PathBuf,
}

impl FileNotificationForwarderPersistence {
    /// Keep the lists in the file at `path`.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(Error::OutOfRange(
                "Notification Forwarder persistence path must not be empty".into(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// The file the lists are kept in.
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
    Error::Encoding(format!("Notification Forwarder file {reason}"))
}

/// Decode `bytes` as one element after another, refusing more than `cap`.
fn decode_capped<T>(
    bytes: &[u8],
    cap: usize,
    decode: impl Fn(&[u8], usize) -> Result<(T, usize), Error>,
) -> Result<Vec<T>, Error> {
    let mut list = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if list.len() == cap {
            return Err(corrupt("holds more entries than the cap"));
        }
        let (element, next) =
            decode(bytes, offset).map_err(|_| corrupt("holds an entry that does not decode"))?;
        list.push(element);
        offset = next;
    }
    Ok(list)
}

impl NotificationForwarderPersistence for FileNotificationForwarderPersistence {
    fn load(&self, forwarder: ObjectIdentifier) -> Result<Option<ForwarderSnapshot>, Error> {
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
        if bytes[OID_AT..WRITTEN_AT] != forwarder.encode() {
            return Err(corrupt("belongs to another object"));
        }
        let length = u32::from_be_bytes(bytes[LENGTH_AT..HEADER_LEN].try_into().unwrap());
        let split = usize::try_from(length)
            .ok()
            .and_then(|length| HEADER_LEN.checked_add(length))
            .filter(|split| *split <= bytes.len())
            .ok_or_else(|| corrupt("has a Recipient_List past its end"))?;
        let recipient_list = &bytes[HEADER_LEN..split];
        let recipient_list = match bytes[WRITTEN_AT] {
            0 if recipient_list.is_empty() => None,
            1 => Some(decode_capped(
                recipient_list,
                MAX_RECIPIENT_LIST_DESTINATIONS,
                decode_destination,
            )?),
            _ => return Err(corrupt("has no valid header")),
        };
        Ok(Some(ForwarderSnapshot {
            recipient_list,
            subscribed_recipients: decode_capped(
                &bytes[split..],
                MAX_SUBSCRIBED_RECIPIENTS,
                decode_event_notification_subscription,
            )?,
        }))
    }

    fn save(&self, forwarder: ObjectIdentifier, snapshot: &ForwarderSnapshot) -> Result<(), Error> {
        let mut recipient_list = BytesMut::new();
        if let Some(list) = &snapshot.recipient_list {
            encode_destination_list(&mut recipient_list, list)?;
        }
        let mut bytes = BytesMut::with_capacity(HEADER_LEN + recipient_list.len() + 1024);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&forwarder.encode());
        bytes.extend_from_slice(&[u8::from(snapshot.recipient_list.is_some())]);
        let length = u32::try_from(recipient_list.len())
            .map_err(|_| Error::OutOfRange("Recipient_List too long to save".into()))?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&recipient_list);
        encode_event_notification_subscription_list(&mut bytes, &snapshot.subscribed_recipients)?;
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
        // The new lists are in place, so the save has landed whatever the
        // directory sync finds.
        sync_parent_dir(&self.path);
        Ok(())
    }
}
