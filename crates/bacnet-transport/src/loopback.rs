//! In-process loopback transport for gateway composition.
//!
//! `LoopbackTransport` implements [`TransportPort`] using `tokio::sync::mpsc`
//! channels. A pair of loopback transports can be created with [`LoopbackTransport::pair`],
//! where sending on one side delivers to the other. This enables the gateway's
//! client and server to connect to the router via in-process channels rather
//! than real network sockets.
//!
//! The peer receives every frame, whatever MAC it was sent to.
//! [`LoopbackTransport::record_unicast_destinations`] reports those MACs, so a
//! test can see where each unicast went.

use std::sync::{Mutex, PoisonError};

use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::port::{ReceivedNpdu, TransportPort, TransportProvenance};

/// In-process loopback transport backed by mpsc channels.
pub struct LoopbackTransport {
    /// This transport's local MAC address.
    local_mac: MacAddr,
    /// Sender to deliver NPDUs to the peer.
    peer_tx: mpsc::Sender<ReceivedNpdu>,
    /// Receiver for NPDUs from the peer. Taken by `start()`.
    self_rx: Option<mpsc::Receiver<ReceivedNpdu>>,
    /// Where each unicast's destination MAC goes, once
    /// [`Self::record_unicast_destinations`] asks for it.
    unicast_destinations: Option<mpsc::UnboundedSender<MacAddr>>,
    /// Held while a recorded unicast is queued for the peer, so concurrent
    /// sends record their MACs in the order the peer receives the frames.
    record_order: Mutex<()>,
}

impl LoopbackTransport {
    /// Create a connected pair of loopback transports.
    ///
    /// Each transport has its own MAC address. Sending on transport A delivers
    /// to transport B's receive channel, and vice versa.
    pub fn pair(mac_a: impl Into<MacAddr>, mac_b: impl Into<MacAddr>) -> (Self, Self) {
        /// NPDU receive channel capacity for loopback (matches high-throughput transports).
        const NPDU_CHANNEL_CAPACITY: usize = 256;

        let (tx_a, rx_a) = mpsc::channel(NPDU_CHANNEL_CAPACITY);
        let (tx_b, rx_b) = mpsc::channel(NPDU_CHANNEL_CAPACITY);

        let a = Self::new(mac_a.into(), tx_b, rx_a); // A sends to B's rx
        let b = Self::new(mac_b.into(), tx_a, rx_b); // B sends to A's rx
        (a, b)
    }

    fn new(
        local_mac: MacAddr,
        peer_tx: mpsc::Sender<ReceivedNpdu>,
        self_rx: mpsc::Receiver<ReceivedNpdu>,
    ) -> Self {
        Self {
            local_mac,
            peer_tx,
            self_rx: Some(self_rx),
            unicast_destinations: None,
            record_order: Mutex::new(()),
        }
    }

    /// Report the destination MAC of each unicast this transport sends from
    /// now on (#1243).
    ///
    /// The returned receiver gets the MAC given to each
    /// [`send_unicast`](TransportPort::send_unicast) that reaches the peer, in
    /// the order the peer receives those frames: the peer's n-th frame with
    /// `link_layer_group` false went to the n-th MAC here. Broadcasts add
    /// nothing. Take the receiver before handing the transport to a router or
    /// network layer.
    ///
    /// The record is unbounded until the receiver is dropped, which stops it.
    /// A later call replaces the earlier receiver.
    pub fn record_unicast_destinations(&mut self) -> mpsc::UnboundedReceiver<MacAddr> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.unicast_destinations = Some(tx);
        rx
    }
}

fn peer_closed() -> Error {
    Error::Encoding("loopback peer channel closed".to_string())
}

impl TransportPort for LoopbackTransport {
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        self.self_rx
            .take()
            .ok_or_else(|| Error::Encoding("loopback transport already started".to_string()))
    }

    async fn stop(&mut self) -> Result<(), Error> {
        // Nothing to clean up — channels drop naturally.
        Ok(())
    }

    async fn send_unicast(&self, npdu: &[u8], mac: &[u8]) -> Result<(), Error> {
        let msg = ReceivedNpdu {
            direct_response: None,
            npdu: Bytes::copy_from_slice(npdu),
            source_mac: self.local_mac.clone(),
            link_layer_group: false,
            data_attributes: Vec::new(),
            provenance: TransportProvenance::unverified(),
            reply_tx: None,
        };
        let Some(destinations) = self.unicast_destinations.as_ref() else {
            return self.peer_tx.send(msg).await.map_err(|_| peer_closed());
        };
        // Wait for room first, then record the MAC and queue the frame under
        // one lock: the record and the peer's queue then share one order.
        let permit = self.peer_tx.reserve().await.map_err(|_| peer_closed())?;
        let _order = self
            .record_order
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // A dropped record receiver only stops the record.
        let _ = destinations.send(MacAddr::from_slice(mac));
        permit.send(msg);
        Ok(())
    }

    async fn send_broadcast(&self, npdu: &[u8]) -> Result<(), Error> {
        let msg = ReceivedNpdu {
            direct_response: None,
            npdu: Bytes::copy_from_slice(npdu),
            source_mac: self.local_mac.clone(),
            link_layer_group: true,
            data_attributes: Vec::new(),
            provenance: TransportProvenance::unverified(),
            reply_tx: None,
        };
        self.peer_tx.send(msg).await.map_err(|_| peer_closed())
    }

    fn local_receive_apdu_capacity(&self) -> u16 {
        1476
    }

    fn local_mac(&self) -> &[u8] {
        &self.local_mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pair_unicast_a_to_b() {
        let (mut a, mut b) = LoopbackTransport::pair(vec![0x00, 0x01], vec![0x00, 0x02]);
        let mut rx_b = b.start().await.unwrap();
        let _rx_a = a.start().await.unwrap();

        a.send_unicast(b"hello", &[0x00, 0x02]).await.unwrap();
        let npdu = rx_b.recv().await.unwrap();
        assert_eq!(&npdu.npdu[..], b"hello");
        assert_eq!(&npdu.source_mac[..], &[0x00, 0x01]);
        assert!(!npdu.link_layer_group);
    }

    #[tokio::test]
    async fn pair_unicast_b_to_a() {
        let (mut a, mut b) = LoopbackTransport::pair(vec![0x00, 0x01], vec![0x00, 0x02]);
        let mut rx_a = a.start().await.unwrap();
        let _rx_b = b.start().await.unwrap();

        b.send_unicast(b"world", &[0x00, 0x01]).await.unwrap();
        let npdu = rx_a.recv().await.unwrap();
        assert_eq!(&npdu.npdu[..], b"world");
        assert_eq!(&npdu.source_mac[..], &[0x00, 0x02]);
        assert!(!npdu.link_layer_group);
    }

    #[tokio::test]
    async fn pair_broadcast() {
        let (mut a, mut b) = LoopbackTransport::pair(vec![0x00, 0x01], vec![0x00, 0x02]);
        let mut rx_b = b.start().await.unwrap();
        let _rx_a = a.start().await.unwrap();

        a.send_broadcast(b"bcast").await.unwrap();
        let npdu = rx_b.recv().await.unwrap();
        assert_eq!(&npdu.npdu[..], b"bcast");
        assert!(npdu.link_layer_group);
    }

    #[tokio::test]
    async fn start_twice_fails() {
        let (mut a, _b) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
        let _rx = a.start().await.unwrap();
        assert!(a.start().await.is_err());
    }

    #[tokio::test]
    async fn recorded_unicast_destinations_follow_the_peers_frames() {
        let (mut a, mut b) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
        let mut destinations = a.record_unicast_destinations();
        let mut rx_b = b.start().await.unwrap();

        // The peer gets all three frames, the first to a MAC not its own.
        a.send_unicast(b"one", &[0x50]).await.unwrap();
        a.send_broadcast(b"two").await.unwrap();
        a.send_unicast(b"three", &[0x02]).await.unwrap();
        for (npdu, group) in [(&b"one"[..], false), (b"two", true), (b"three", false)] {
            let frame = rx_b.recv().await.unwrap();
            assert_eq!(&frame.npdu[..], npdu);
            assert_eq!(frame.link_layer_group, group);
        }
        assert_eq!(destinations.try_recv().unwrap().as_slice(), [0x50]);
        assert_eq!(destinations.try_recv().unwrap().as_slice(), [0x02]);
        assert!(
            destinations.try_recv().is_err(),
            "a broadcast records nothing"
        );

        // Dropping the receiver stops the record; sending carries on.
        drop(destinations);
        a.send_unicast(b"four", &[0x60]).await.unwrap();
        assert_eq!(&rx_b.recv().await.unwrap().npdu[..], b"four");

        // A unicast that never reaches the peer records nothing.
        let mut destinations = a.record_unicast_destinations();
        drop(rx_b);
        assert!(a.send_unicast(b"five", &[0x70]).await.is_err());
        assert!(destinations.try_recv().is_err());
    }

    #[tokio::test]
    async fn concurrent_unicasts_record_destinations_in_delivery_order() {
        let (mut a, mut b) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
        let mut destinations = a.record_unicast_destinations();
        let mut rx_b = b.start().await.unwrap();
        let a = std::sync::Arc::new(a);

        // Four threads send 300 unicasts between them, more than the peer
        // queue holds, so some wait for room. Each goes to the MAC that
        // matches its bytes.
        let threads: Vec<_> = (0..4u16)
            .map(|thread| {
                let a = std::sync::Arc::clone(&a);
                std::thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap();
                    for i in 0..75 {
                        let id = (thread * 75 + i).to_be_bytes();
                        runtime.block_on(a.send_unicast(&id, &id)).unwrap();
                    }
                })
            })
            .collect();
        for _ in 0..300 {
            let frame = rx_b.recv().await.unwrap();
            let mac = destinations.recv().await.unwrap();
            assert_eq!(mac.as_slice(), &frame.npdu[..]);
        }
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[tokio::test]
    async fn local_mac_correct() {
        let (a, b) = LoopbackTransport::pair(vec![0xAA], vec![0xBB]);
        assert_eq!(a.local_mac(), &[0xAA]);
        assert_eq!(b.local_mac(), &[0xBB]);
    }
}
