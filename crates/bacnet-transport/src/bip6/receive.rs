//! The B/IPv6 receive loop: what happens to one datagram once the socket has
//! admitted it to the selected link.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bacnet_encoding::npdu::decode_npdu;
use bacnet_types::MacAddr;
use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::port::{ReceivedNpdu, TransportProvenance};
use crate::udp_metadata::ReceivedDatagram;

use super::frame::destination_vmac_matches;
use super::ingress::{
    forwarded_npdu_is_trusted, forwarded_source_is_usable, group_destination,
    original_destination_matches, LocalBinding,
};
use super::port::is_bip6_group;
use super::socket::Bip6Socket;
use super::vmac_table::VmacTable;
use super::{
    decode_bvlc6, decode_forwarded_npdu_payload, encode_address_resolution_ack, encode_bip6_mac,
    encode_virtual_address_resolution_ack, Bip6Vmac, Bvlc6Frame, Bvlc6Function,
};

/// What the receive loop needs besides the datagram itself.
pub(super) struct Receiver {
    /// The transport's socket, also used for address-resolution replies.
    pub(super) socket: Arc<Bip6Socket>,
    /// Where NPDUs go up to the network layer.
    pub(super) tx: mpsc::Sender<ReceivedNpdu>,
    /// This node's B/IPv6 address as a MAC, to ignore its own frames.
    pub(super) local_mac: [u8; 18],
    /// This node's virtual MAC.
    pub(super) vmac: Bip6Vmac,
    /// The address the socket answers unicast on.
    pub(super) local_ip: Ipv6Addr,
    /// Unicast addresses of the local interfaces.
    pub(super) unicast_ips: Vec<Ipv6Addr>,
    /// Whether the socket is bound to the wildcard address.
    pub(super) wildcard_bind: bool,
    /// The BBMD this node is registered with as a foreign device, if any.
    pub(super) foreign_bbmd: Option<(Ipv6Addr, u16)>,
    /// Learned VMAC to address mappings.
    pub(super) vmac_table: VmacTable,
    /// Forwarded-NPDUs refused for a group origin (#1493), shared with the
    /// transport.
    pub(super) forwarded_group_origin_drops: Arc<AtomicU64>,
}

impl Receiver {
    /// Receive until the socket fails.
    pub(super) async fn run(self) {
        let mut recv_buf = vec![0u8; 2048];
        loop {
            match self.socket.recv_from(&mut recv_buf).await {
                Ok(received) => {
                    self.handle_datagram(&recv_buf[..received.len], &received)
                        .await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    debug!(error = %e, "Dropping UDP datagram with invalid destination metadata");
                }
                Err(e) => {
                    warn!(error = %e, "IPv6 UDP recv error");
                    break;
                }
            }
        }
    }

    fn binding(&self) -> LocalBinding<'_> {
        LocalBinding {
            ip: self.local_ip,
            vmac: self.vmac,
            unicast_ips: &self.unicast_ips,
            wildcard_bind: self.wildcard_bind,
        }
    }

    /// Decode one datagram, drop it if its addressing does not fit its BVLC
    /// function, and otherwise act on it.
    pub(super) async fn handle_datagram(&self, data: &[u8], received: &ReceivedDatagram) {
        let frame = match decode_bvlc6(data) {
            Ok(frame) => frame,
            Err(e) => {
                warn!(error = %e, "Failed to decode BVLC6 frame");
                return;
            }
        };
        if !destination_vmac_matches(frame.function, frame.destination_vmac, self.vmac) {
            debug!(
                function = frame.function.to_byte(),
                destination_vmac = ?frame.destination_vmac,
                "Dropping BVLC6 message addressed to another VMAC"
            );
            return;
        }
        if !original_destination_matches(
            frame.function,
            received.destination,
            frame.destination_vmac,
            &self.binding(),
            received.os_group_delivery,
        ) {
            debug!(
                function = frame.function.to_byte(),
                destination = %received.destination,
                "Dropping BVLC6/IP or Destination-VMAC mismatch"
            );
            return;
        }
        if frame.function == Bvlc6Function::ForwardedNpdu
            && !forwarded_npdu_is_trusted(
                received.peer,
                received.destination,
                received.os_group_delivery,
                self.local_ip,
                &self.unicast_ips,
                self.wildcard_bind,
                self.foreign_bbmd,
            )
        {
            debug!(
                peer = %received.peer,
                destination = %received.destination,
                "Dropping Forwarded-NPDU from an untrusted path"
            );
            return;
        }
        // Forwarded-NPDU's source VMAC identifies the original node, not the
        // forwarding BBMD. Its original address is learned from the function
        // payload in `dispatch`.
        if matches!(
            frame.function,
            Bvlc6Function::OriginalUnicast
                | Bvlc6Function::OriginalBroadcast
                | Bvlc6Function::AddressResolution
                | Bvlc6Function::AddressResolutionAck
                | Bvlc6Function::VirtualAddressResolution
                | Bvlc6Function::VirtualAddressResolutionAck
        ) {
            if let SocketAddr::V6(v6) = received.peer {
                self.vmac_table.learn(frame.source_vmac, v6).await;
            }
        }
        self.dispatch(frame, received).await;
    }

    /// Act on a frame whose addressing `handle_datagram` has checked.
    pub(super) async fn dispatch(&self, frame: Bvlc6Frame, received: &ReceivedDatagram) {
        match frame.function {
            Bvlc6Function::OriginalUnicast | Bvlc6Function::OriginalBroadcast => {
                let SocketAddr::V6(v6) = received.peer else {
                    return;
                };
                let source_mac = MacAddr::from_slice(&encode_bip6_mac(*v6.ip(), v6.port()));
                if source_mac[..] == self.local_mac[..] {
                    return;
                }
                // A group delivery if either the function or the address
                // says so: an Original-Unicast-NPDU sent to a multicast group
                // reached every node in it, so a confirmed request in it is
                // never answered as a directed one (Clause 5.4.5.1).
                let link_layer_group = frame.function == Bvlc6Function::OriginalBroadcast
                    || group_destination(received.destination, received.os_group_delivery);
                if self
                    .tx
                    .try_send(ReceivedNpdu {
                        direct_response: None,
                        npdu: frame.payload.clone(),
                        source_mac,
                        link_layer_group,
                        data_attributes: Vec::new(),
                        provenance: TransportProvenance::unverified(),
                        reply_tx: None,
                    })
                    .is_err()
                {
                    warn!("BIP6: NPDU channel full, dropping incoming frame");
                }
            }

            Bvlc6Function::ForwardedNpdu => match decode_forwarded_npdu_payload(&frame.payload) {
                Ok((source_addr, npdu_bytes)) => {
                    // The origin is taken as the NPDU's source, so a group
                    // there would bind a forged I-Am to every node in it, or
                    // send a request's answer to them all. No node sends from
                    // one: the frame is malformed, and counted (#1493).
                    let source_mac = encode_bip6_mac(*source_addr.ip(), source_addr.port());
                    if is_bip6_group(&source_mac) {
                        self.forwarded_group_origin_drops
                            .fetch_add(1, Ordering::Relaxed);
                        debug!(
                            source = %source_addr,
                            "Dropping Forwarded-NPDU whose origin is a group address"
                        );
                        return;
                    }
                    if npdu_bytes.is_empty() {
                        debug!("ForwardedNpdu with no NPDU payload, ignoring");
                        return;
                    }
                    if !forwarded_source_is_usable(source_addr) {
                        debug!(
                            source = %source_addr,
                            "Dropping Forwarded-NPDU with unusable origin"
                        );
                        return;
                    }
                    if decode_npdu(Bytes::copy_from_slice(npdu_bytes)).is_err() {
                        debug!("Dropping Forwarded-NPDU with malformed NPDU");
                        return;
                    }
                    self.vmac_table.learn(frame.source_vmac, source_addr).await;
                    if self
                        .tx
                        .try_send(ReceivedNpdu {
                            direct_response: None,
                            npdu: Bytes::copy_from_slice(npdu_bytes),
                            source_mac: MacAddr::from_slice(&source_mac),
                            link_layer_group: true,
                            data_attributes: Vec::new(),
                            provenance: TransportProvenance::unverified(),
                            reply_tx: None,
                        })
                        .is_err()
                    {
                        warn!("BIP6: NPDU channel full, dropping forwarded frame");
                    }
                }
                Err(e) => {
                    debug!(error = %e, "Failed to decode ForwardedNpdu payload");
                }
            },

            Bvlc6Function::VirtualAddressResolution => {
                // A node receiving VAR at its unicast B/IPv6 address
                // answers with its own VMAC and the requester's VMAC.
                let ack = encode_virtual_address_resolution_ack(&self.vmac, &frame.source_vmac);
                let _ = self.socket.send_to(&ack, received.peer).await;
            }

            Bvlc6Function::AddressResolution => {
                // AR: sender wants to know our B/IPv6 address from our VMAC.
                // destination_vmac is the target being resolved.
                if frame.destination_vmac == Some(self.vmac) {
                    debug!(vmac = ?self.vmac, "Received AR for our VMAC, sending AR-Ack");
                    let ack = encode_address_resolution_ack(&self.vmac, &frame.source_vmac);
                    let _ = self.socket.send_to(&ack, received.peer).await;
                }
            }

            Bvlc6Function::AddressResolutionAck => {
                // AR-ACK: learn the sender's VMAC→address mapping
                // (will be used by VMAC table in future)
                debug!(
                    vmac = ?frame.source_vmac,
                    addr = %received.peer,
                    "Received AR-Ack"
                );
            }

            Bvlc6Function::VirtualAddressResolutionAck => {
                // VAR-ACK: someone responded to our collision check
                if frame.source_vmac == self.vmac {
                    warn!(
                        vmac = ?self.vmac,
                        "BIP6 VMAC collision detected! \
                         Another node responded with our VMAC."
                    );
                }
            }

            Bvlc6Function::Result => {
                // Log BVLC-Result for diagnostics
                if frame.payload.len() >= 2 {
                    let result_code = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
                    if result_code == 0x0000 {
                        debug!("BIP6: BVLC-Result successful");
                    } else {
                        tracing::error!(code = result_code, "BIP6: BVLC-Result NAK");
                    }
                }
            }

            _ => {
                debug!(function = ?frame.function, "Unhandled BVLC6 function");
            }
        }
    }
}
