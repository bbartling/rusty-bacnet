//! The worker layer: the only part of the TUI that is generic over the
//! transport.
//!
//! It owns the `BACnetClient`, turns [`Command`](super::message::Command)s
//! into requests and forwards client notifications to the UI through a
//! bounded channel. When the UI falls behind, events are dropped and counted
//! rather than queued without limit, and the table is resynchronised from the
//! client's own discovery table afterwards.

pub(crate) mod session;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bacnet_client::client::{DeviceCollisionEvent, DeviceEvent, DeviceEventKind};
use bacnet_client::discovery::DiscoveredDevice;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

use super::message::{hex, AddressStyle, DeviceRow, WorkerEvent};

/// Capacity of the worker-to-UI channel.
pub(crate) const EVENT_CHANNEL_CAPACITY: usize = 1_024;

/// Capacity of the UI-to-worker channel; commands are user actions.
pub(crate) const COMMAND_CHANNEL_CAPACITY: usize = 16;

/// Result of offering an event to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    /// Queued.
    Sent,
    /// The channel was full; the event was counted as dropped.
    Dropped,
    /// The UI has gone.
    Closed,
}

/// The sending side of the worker-to-UI channel, with the dropped counter.
#[derive(Clone)]
pub(crate) struct EventSink {
    tx: mpsc::Sender<WorkerEvent>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    /// A sink and its receiver, holding at most `capacity` events.
    pub(crate) fn channel(capacity: usize) -> (Self, mpsc::Receiver<WorkerEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        let sink = Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (sink, rx)
    }

    /// The shared dropped-events counter the status bar shows.
    pub(crate) fn dropped_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dropped)
    }

    /// Count `n` events lost upstream (a lagging broadcast receiver).
    pub(crate) fn add_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// Queue a high-rate event without waiting; drop and count it when full.
    pub(crate) fn offer(&self, event: WorkerEvent) -> Offer {
        match self.tx.try_send(event) {
            Ok(()) => Offer::Sent,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.add_dropped(1);
                Offer::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Offer::Closed,
        }
    }

    /// Queue a rare control event (connect, operation progress), waiting for
    /// room. Returns false if the UI has gone.
    pub(crate) async fn deliver(&self, event: WorkerEvent) -> bool {
        self.tx.send(event).await.is_ok()
    }
}

/// Folds the client's device and collision broadcasts into UI events.
pub(crate) struct DeviceFeed {
    style: AddressStyle,
    /// Something was lost, so the UI's table may be out of date.
    pub(crate) needs_resync: bool,
    /// `device_events()` is still open.
    pub(crate) devices_open: bool,
    /// `device_collision_events()` is still open.
    pub(crate) collisions_open: bool,
}

impl DeviceFeed {
    /// A feed formatting addresses with `style`.
    pub(crate) fn new(style: AddressStyle) -> Self {
        Self {
            style,
            needs_resync: false,
            devices_open: true,
            collisions_open: true,
        }
    }

    /// Convert a client row for the UI.
    pub(crate) fn row(&self, device: &DiscoveredDevice) -> DeviceRow {
        let address = match (&device.source_network, &device.source_address) {
            (Some(_), Some(remote)) => format!(
                "{} via {}",
                hex(remote.as_slice()),
                self.style.format(device.mac_address.as_slice())
            ),
            _ => self.style.format(device.mac_address.as_slice()),
        };
        DeviceRow {
            instance: device.object_identifier.instance_number(),
            address,
            network: device.source_network,
            vendor_id: device.vendor_id,
            max_apdu: device.max_apdu_length,
            segmentation: device.segmentation_supported,
            last_seen: device.last_seen,
        }
    }

    /// Handle one receive from `device_events()`.
    pub(crate) fn on_device(&mut self, sink: &EventSink, received: Result<DeviceEvent, RecvError>) {
        match received {
            Ok(event) => {
                let row = self.row(&event.device);
                let event = match event.kind {
                    DeviceEventKind::Discovered => WorkerEvent::Discovered(row),
                    DeviceEventKind::Updated => WorkerEvent::Updated(row),
                    DeviceEventKind::Lost => WorkerEvent::Lost(row),
                };
                if sink.offer(event) == Offer::Dropped {
                    self.needs_resync = true;
                }
            }
            Err(RecvError::Lagged(missed)) => {
                sink.add_dropped(missed);
                self.needs_resync = true;
            }
            Err(RecvError::Closed) => self.devices_open = false,
        }
    }

    /// Handle one receive from `device_collision_events()`, returning the
    /// event to deliver. Collisions are rare and important, so the caller
    /// delivers them with [`EventSink::deliver`] rather than risk a drop.
    pub(crate) fn on_collision(
        &mut self,
        sink: &EventSink,
        received: Result<DeviceCollisionEvent, RecvError>,
    ) -> Option<WorkerEvent> {
        match received {
            Ok(event) => Some(WorkerEvent::Collision {
                retained: self.row(&event.retained),
                incoming: self.row(&event.incoming),
            }),
            Err(RecvError::Lagged(missed)) => {
                sink.add_dropped(missed);
                None
            }
            Err(RecvError::Closed) => {
                self.collisions_open = false;
                None
            }
        }
    }
}
