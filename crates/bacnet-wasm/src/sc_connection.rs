//! BACnet/SC connection state machine for WASM.
//!
//! Ported from `bacnet-transport/src/sc.rs` — pure sync logic with no tokio
//! dependencies. Manages the Connect → Connected → Disconnect lifecycle.

use bytes::Bytes;

use crate::data_attributes::{self, DataAttribute};
use crate::sc_frame::{
    decode_sc_bvlc_result, is_broadcast_vmac, ScBvlcResult, ScFunction, ScMessage, Vmac,
};
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;

const DEFAULT_MAX_BVLC_LENGTH: u16 = 1476;

/// BACnet/SC connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScConnectionState {
    /// Not connected.
    Disconnected,
    /// Connect-Request sent, waiting for Connect-Accept.
    Connecting,
    /// Connected and operational.
    Connected,
    /// Disconnect requested.
    Disconnecting,
}

/// BACnet/SC hub connection manager.
pub struct ScConnection {
    pub state: ScConnectionState,
    pub local_vmac: Vmac,
    /// Device UUID (16 bytes, RFC 4122) per AB.1.5.3.
    pub device_uuid: [u8; 16],
    pub hub_vmac: Option<Vmac>,
    /// Maximum encoded BACnet/SC BVLC message length this node can accept.
    pub max_bvlc_length: u16,
    /// Maximum NPDU length this node can accept.
    pub max_apdu_length: u16,
    /// Maximum encoded BACnet/SC BVLC message length the hub can accept.
    pub hub_max_bvlc_length: u16,
    /// Maximum NPDU length the hub can accept.
    pub hub_max_apdu_length: u16,
    next_message_id: u16,
    pending_connect_message_id: Option<u16>,
    pub disconnect_ack_to_send: Option<ScMessage>,
}

/// BACnet/SC NPDU received by a WASM/browser client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedScNpdu {
    /// Raw NPDU bytes.
    pub npdu: Bytes,
    /// Source VMAC, or the unknown VMAC when absent.
    pub source_vmac: Vmac,
    /// BACnet/SC Data Options exposed as data attributes.
    pub data_attributes: Vec<DataAttribute>,
}

impl ScConnection {
    pub fn new(local_vmac: Vmac) -> Self {
        Self::new_with_device_uuid(local_vmac, [0u8; 16])
    }

    pub fn new_with_device_uuid(local_vmac: Vmac, device_uuid: [u8; 16]) -> Self {
        Self {
            state: ScConnectionState::Disconnected,
            local_vmac,
            device_uuid,
            hub_vmac: None,
            max_bvlc_length: DEFAULT_MAX_BVLC_LENGTH,
            max_apdu_length: DEFAULT_MAX_BVLC_LENGTH,
            hub_max_bvlc_length: DEFAULT_MAX_BVLC_LENGTH,
            hub_max_apdu_length: DEFAULT_MAX_BVLC_LENGTH,
            next_message_id: 1,
            pending_connect_message_id: None,
            disconnect_ack_to_send: None,
        }
    }

    pub fn next_id(&mut self) -> u16 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        id
    }

    /// Build a Connect-Request message.
    ///
    /// AB.2.10.1: VMAC(6) + Device_UUID(16) + Max-BVLC-Length(2) + Max-NPDU-Length(2) = 26 bytes.
    /// No Originating/Destination Virtual Address.
    pub fn build_connect_request(&mut self) -> ScMessage {
        self.state = ScConnectionState::Connecting;
        let message_id = self.next_id();
        self.pending_connect_message_id = Some(message_id);
        let mut payload_buf = Vec::with_capacity(26);
        payload_buf.extend_from_slice(&self.local_vmac);
        payload_buf.extend_from_slice(&self.device_uuid);
        payload_buf.extend_from_slice(&self.max_bvlc_length.to_be_bytes());
        payload_buf.extend_from_slice(&self.max_apdu_length.to_be_bytes());
        ScMessage {
            function: ScFunction::ConnectRequest,
            message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from(payload_buf),
        }
    }

    /// Handle a received Connect-Accept (AB.2.11.1).
    pub fn handle_connect_accept(&mut self, msg: &ScMessage) -> bool {
        if self.state != ScConnectionState::Connecting {
            return false;
        }
        if msg.function != ScFunction::ConnectAccept {
            return false;
        }
        if self.pending_connect_message_id != Some(msg.message_id) {
            return false;
        }
        if msg.payload.len() != 26 {
            return false;
        }
        self.pending_connect_message_id = None;
        let mut hub_vmac = [0u8; 6];
        hub_vmac.copy_from_slice(&msg.payload[0..6]);
        self.hub_vmac = Some(hub_vmac);
        self.hub_max_bvlc_length = u16::from_be_bytes([msg.payload[22], msg.payload[23]]);
        self.hub_max_apdu_length = u16::from_be_bytes([msg.payload[24], msg.payload[25]]);
        self.state = ScConnectionState::Connected;
        true
    }

    pub fn abort_connect(&mut self) {
        self.state = ScConnectionState::Disconnected;
        self.pending_connect_message_id = None;
    }

    /// Handle a BVLC-Result received while waiting for Connect-Accept.
    ///
    /// Returns true when AB.6.2.2 duplicate-VMAC recovery installed the
    /// supplied replacement Random-48 VMAC.
    pub fn handle_connect_result(
        &mut self,
        result_message_id: u16,
        result: &ScBvlcResult,
        replacement_vmac: Option<Vmac>,
    ) -> Result<bool, Error> {
        let duplicate_vmac = self.connect_result_requires_random48_vmac(result_message_id, result);
        self.abort_connect();

        if duplicate_vmac {
            let replacement_vmac = replacement_vmac.ok_or_else(|| {
                Error::Encoding("duplicate VMAC recovery requires a replacement VMAC".into())
            })?;
            self.local_vmac = replacement_vmac;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn connect_result_requires_random48_vmac(
        &self,
        result_message_id: u16,
        result: &ScBvlcResult,
    ) -> bool {
        if self.pending_connect_message_id != Some(result_message_id) {
            return false;
        }

        let ScBvlcResult::Nak {
            result_for,
            error_class,
            error_code,
            ..
        } = result
        else {
            return false;
        };

        *result_for == ScFunction::ConnectRequest
            && *error_class == ErrorClass::COMMUNICATION.to_raw()
            && *error_code == ErrorCode::NODE_DUPLICATE_VMAC.to_raw()
    }

    /// Build a Disconnect-Request message.
    /// AB.2.12.1: No Originating/Destination Virtual Address.
    pub fn build_disconnect_request(&mut self) -> Result<ScMessage, Error> {
        if self.hub_vmac.is_none() {
            return Err(Error::Encoding(
                "cannot build DisconnectRequest: no hub VMAC (not connected)".into(),
            ));
        }
        self.state = ScConnectionState::Disconnecting;
        Ok(ScMessage {
            function: ScFunction::DisconnectRequest,
            message_id: self.next_id(),
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::new(),
        })
    }

    /// Build a Heartbeat-Request message.
    /// AB.2.14.1: No Originating/Destination Virtual Address.
    pub fn build_heartbeat(&mut self) -> ScMessage {
        ScMessage {
            function: ScFunction::HeartbeatRequest,
            message_id: self.next_id(),
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::new(),
        }
    }

    /// Build a Heartbeat-ACK message.
    /// AB.2.15.1: No Originating/Destination Virtual Address.
    pub fn build_heartbeat_ack(&self, request_message_id: u16) -> ScMessage {
        ScMessage {
            function: ScFunction::HeartbeatAck,
            message_id: request_message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::new(),
        }
    }

    /// Build an Encapsulated-NPDU message.
    pub fn build_encapsulated_npdu(&mut self, dest_vmac: Vmac, npdu: &[u8]) -> ScMessage {
        self.build_encapsulated_npdu_with_data_attributes(dest_vmac, npdu, &[])
            .expect("empty data attributes are valid")
    }

    /// Build an Encapsulated-NPDU message with BACnet/SC Data Options.
    pub fn build_encapsulated_npdu_with_data_attributes(
        &mut self,
        dest_vmac: Vmac,
        npdu: &[u8],
        data_attributes: &[DataAttribute],
    ) -> Result<ScMessage, Error> {
        Ok(ScMessage {
            function: ScFunction::EncapsulatedNpdu,
            message_id: self.next_id(),
            originating_vmac: None,
            destination_vmac: Some(dest_vmac),
            dest_options: Vec::new(),
            data_options: data_attributes::to_data_options(data_attributes)?,
            payload: Bytes::copy_from_slice(npdu),
        })
    }

    /// Return the fail-closed Result response for an unsupported Must Understand Data Option.
    pub fn unsupported_must_understand_result(&self, msg: &ScMessage) -> Option<Option<ScMessage>> {
        data_attributes::unsupported_must_understand_result(msg)
    }

    /// Handle a received message. Returns NPDU data when it's an Encapsulated-NPDU for us.
    pub fn handle_received(&mut self, msg: &ScMessage) -> Option<ReceivedScNpdu> {
        match msg.function {
            ScFunction::EncapsulatedNpdu => {
                if self.state != ScConnectionState::Connected {
                    return None;
                }
                if let Some(dest) = msg.destination_vmac {
                    if !is_broadcast_vmac(&dest) {
                        return None;
                    }
                }
                if msg.payload.len() > self.max_apdu_length as usize {
                    return None;
                }
                let source = msg.originating_vmac.unwrap_or([0; 6]);
                Some(ReceivedScNpdu {
                    npdu: msg.payload.clone(),
                    source_vmac: source,
                    data_attributes: data_attributes::from_data_options(msg),
                })
            }
            ScFunction::HeartbeatRequest => None,
            ScFunction::DisconnectRequest => {
                self.state = ScConnectionState::Disconnected;
                // AB.2.13.1: Disconnect-ACK has no VMACs
                self.disconnect_ack_to_send = Some(ScMessage {
                    function: ScFunction::DisconnectAck,
                    message_id: msg.message_id,
                    originating_vmac: None,
                    destination_vmac: None,
                    dest_options: Vec::new(),
                    data_options: Vec::new(),
                    payload: Bytes::new(),
                });
                None
            }
            ScFunction::DisconnectAck => {
                if self.state == ScConnectionState::Disconnecting {
                    self.state = ScConnectionState::Disconnected;
                }
                None
            }
            ScFunction::Result => {
                match decode_sc_bvlc_result(msg) {
                    Ok(ScBvlcResult::Ack { .. }) => {}
                    Ok(ScBvlcResult::Nak { .. }) | Err(_) => {
                        self.state = ScConnectionState::Disconnected;
                        self.pending_connect_message_id = None;
                    }
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_handshake() {
        let vmac = [1, 2, 3, 4, 5, 6];
        let mut conn = ScConnection::new(vmac);
        conn.max_bvlc_length = 1200;
        conn.max_apdu_length = 900;
        assert_eq!(conn.state, ScConnectionState::Disconnected);

        let req = conn.build_connect_request();
        assert_eq!(conn.state, ScConnectionState::Connecting);
        assert_eq!(req.function, ScFunction::ConnectRequest);
        // AB.2.10.1: no VMACs, 26-byte payload
        assert!(req.originating_vmac.is_none());
        assert_eq!(req.payload.len(), 26);
        assert_eq!(u16::from_be_bytes([req.payload[22], req.payload[23]]), 1200);
        assert_eq!(u16::from_be_bytes([req.payload[24], req.payload[25]]), 900);

        // Simulate ConnectAccept with 26-byte payload
        let hub_vmac = [7, 8, 9, 10, 11, 12];
        let mut accept_payload = Vec::with_capacity(26);
        accept_payload.extend_from_slice(&hub_vmac);
        accept_payload.extend_from_slice(&[0u8; 16]); // Device UUID
        accept_payload.extend_from_slice(&1100u16.to_be_bytes());
        accept_payload.extend_from_slice(&480u16.to_be_bytes());
        let accept = ScMessage {
            function: ScFunction::ConnectAccept,
            message_id: req.message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from(accept_payload),
        };
        assert!(conn.handle_connect_accept(&accept));
        assert_eq!(conn.state, ScConnectionState::Connected);
        assert_eq!(conn.hub_vmac, Some(hub_vmac));
        assert_eq!(conn.hub_max_bvlc_length, 1100);
        assert_eq!(conn.hub_max_apdu_length, 480);
    }

    #[test]
    fn connect_accept_wrong_state() {
        let mut conn = ScConnection::new([1; 6]);
        // Not in Connecting state
        let msg = ScMessage {
            function: ScFunction::ConnectAccept,
            message_id: 1,
            originating_vmac: Some([2; 6]),
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from(vec![0; 10]),
        };
        assert!(!conn.handle_connect_accept(&msg));
    }

    #[test]
    fn connect_accept_rejects_wrong_message_id() {
        let mut conn = ScConnection::new([1; 6]);
        let req = conn.build_connect_request();
        let hub_vmac = [2; 6];
        let mut payload = Vec::with_capacity(26);
        payload.extend_from_slice(&hub_vmac);
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&1476u16.to_be_bytes());
        payload.extend_from_slice(&1476u16.to_be_bytes());

        let wrong_accept = ScMessage {
            function: ScFunction::ConnectAccept,
            message_id: req.message_id.wrapping_add(1),
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from(payload.clone()),
        };
        assert!(!conn.handle_connect_accept(&wrong_accept));
        assert_eq!(conn.state, ScConnectionState::Connecting);
        assert_eq!(conn.hub_vmac, None);

        let right_accept = ScMessage {
            function: ScFunction::ConnectAccept,
            message_id: req.message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from(payload),
        };
        assert!(conn.handle_connect_accept(&right_accept));
        assert_eq!(conn.state, ScConnectionState::Connected);
        assert_eq!(conn.hub_vmac, Some(hub_vmac));
    }

    #[test]
    fn connect_accept_rejects_short_payload() {
        let mut conn = ScConnection::new([1; 6]);
        let req = conn.build_connect_request();
        let short_accept = ScMessage {
            function: ScFunction::ConnectAccept,
            message_id: req.message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[2; 6]),
        };

        assert!(!conn.handle_connect_accept(&short_accept));
        assert_eq!(conn.state, ScConnectionState::Connecting);
        assert_eq!(conn.hub_vmac, None);
    }

    #[test]
    fn disconnect_request_and_ack() {
        let vmac = [1; 6];
        let hub_vmac = [2; 6];
        let mut conn = ScConnection::new(vmac);
        conn.state = ScConnectionState::Connected;
        conn.hub_vmac = Some(hub_vmac);

        let req = conn.build_disconnect_request().unwrap();
        assert_eq!(conn.state, ScConnectionState::Disconnecting);
        assert_eq!(req.function, ScFunction::DisconnectRequest);
        // AB.2.12.1: no VMACs
        assert!(req.originating_vmac.is_none());
        assert!(req.destination_vmac.is_none());

        // Receive DisconnectAck
        let ack = ScMessage {
            function: ScFunction::DisconnectAck,
            message_id: req.message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::new(),
        };
        conn.handle_received(&ack);
        assert_eq!(conn.state, ScConnectionState::Disconnected);
    }

    #[test]
    fn disconnect_without_hub_vmac() {
        let mut conn = ScConnection::new([1; 6]);
        assert!(conn.build_disconnect_request().is_err());
    }

    #[test]
    fn encapsulated_npdu_round_trip() {
        let vmac = [1; 6];
        let hub_vmac = [2; 6];
        let mut conn = ScConnection::new(vmac);
        conn.state = ScConnectionState::Connected;
        conn.hub_vmac = Some(hub_vmac);

        let npdu = vec![0x01, 0x04, 0x00];
        let msg = conn.build_encapsulated_npdu([3; 6], &npdu);
        assert_eq!(msg.function, ScFunction::EncapsulatedNpdu);
        assert_eq!(msg.destination_vmac, Some([3; 6]));
        assert_eq!(msg.payload.as_ref(), &npdu[..]);
    }

    #[test]
    fn handle_encapsulated_npdu_hub_unicast() {
        let vmac = [1; 6];
        let mut conn = ScConnection::new(vmac);
        conn.state = ScConnectionState::Connected;

        let msg = ScMessage {
            function: ScFunction::EncapsulatedNpdu,
            message_id: 42,
            originating_vmac: Some([2; 6]),
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x01, 0x04]),
        };
        let result = conn.handle_received(&msg);
        assert!(result.is_some());
        let received = result.unwrap();
        assert_eq!(received.npdu.as_ref(), &[0x01, 0x04]);
        assert_eq!(received.source_vmac, [2; 6]);
        assert!(received.data_attributes.is_empty());
    }

    #[test]
    fn handle_encapsulated_npdu_rejects_oversized_local_npdu() {
        let vmac = [1; 6];
        let mut conn = ScConnection::new(vmac);
        conn.state = ScConnectionState::Connected;
        conn.max_apdu_length = 1;

        let msg = ScMessage {
            function: ScFunction::EncapsulatedNpdu,
            message_id: 42,
            originating_vmac: Some([2; 6]),
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x01, 0x04]),
        };
        assert!(conn.handle_received(&msg).is_none());
    }

    #[test]
    fn handle_encapsulated_npdu_drops_non_broadcast_destination_from_hub() {
        let vmac = [1; 6];
        let mut conn = ScConnection::new(vmac);
        conn.state = ScConnectionState::Connected;

        let msg = ScMessage {
            function: ScFunction::EncapsulatedNpdu,
            message_id: 42,
            originating_vmac: Some([2; 6]),
            destination_vmac: Some(vmac),
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x01]),
        };
        assert!(conn.handle_received(&msg).is_none());
    }

    #[test]
    fn handle_encapsulated_npdu_broadcast() {
        let vmac = [1; 6];
        let mut conn = ScConnection::new(vmac);
        conn.state = ScConnectionState::Connected;

        let msg = ScMessage {
            function: ScFunction::EncapsulatedNpdu,
            message_id: 42,
            originating_vmac: Some([2; 6]),
            destination_vmac: Some([0xFF; 6]), // broadcast
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x01]),
        };
        assert!(conn.handle_received(&msg).is_some());
    }

    #[test]
    fn handle_disconnect_request_generates_ack() {
        let vmac = [1; 6];
        let mut conn = ScConnection::new(vmac);
        conn.state = ScConnectionState::Connected;

        let msg = ScMessage {
            function: ScFunction::DisconnectRequest,
            message_id: 99,
            originating_vmac: Some([2; 6]),
            destination_vmac: Some(vmac),
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::new(),
        };
        conn.handle_received(&msg);
        assert_eq!(conn.state, ScConnectionState::Disconnected);
        let ack = conn.disconnect_ack_to_send.take().unwrap();
        assert_eq!(ack.function, ScFunction::DisconnectAck);
        assert_eq!(ack.message_id, 99);
        // AB.2.13.1: no VMACs on DisconnectAck
        assert!(ack.originating_vmac.is_none());
        assert!(ack.destination_vmac.is_none());
    }

    #[test]
    fn handle_bvlc_result_ack_keeps_connected() {
        let mut conn = ScConnection::new([1; 6]);
        conn.state = ScConnectionState::Connected;

        let msg = ScMessage {
            function: ScFunction::Result,
            message_id: 1,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x0C, 0x00]),
        };
        conn.handle_received(&msg);
        assert_eq!(conn.state, ScConnectionState::Connected);
    }

    #[test]
    fn handle_bvlc_result_nak_disconnects() {
        let mut conn = ScConnection::new([1; 6]);
        conn.state = ScConnectionState::Connected;

        let msg = ScMessage {
            function: ScFunction::Result,
            message_id: 1,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01]),
        };
        conn.handle_received(&msg);
        assert_eq!(conn.state, ScConnectionState::Disconnected);
    }

    #[test]
    fn handle_connect_result_duplicate_vmac_installs_replacement() {
        let mut conn = ScConnection::new([1; 6]);
        let req = conn.build_connect_request();
        let replacement = [0x12, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let msg = ScMessage {
            function: ScFunction::Result,
            message_id: req.message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x06, 0x01, 0x00, 0x00, 0x07, 0x00, 0x97]),
        };
        let result = decode_sc_bvlc_result(&msg).unwrap();

        assert!(conn
            .handle_connect_result(req.message_id, &result, Some(replacement))
            .unwrap());
        assert_eq!(conn.state, ScConnectionState::Disconnected);
        assert_eq!(conn.local_vmac, replacement);

        let retry = conn.build_connect_request();
        assert_eq!(&retry.payload[0..6], replacement.as_slice());
    }

    #[test]
    fn handle_connect_result_duplicate_vmac_wrong_message_id_does_not_replace_vmac() {
        let original = [0x22, 1, 2, 3, 4, 5];
        let replacement = [0x12, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut conn = ScConnection::new(original);
        let req = conn.build_connect_request();
        let msg = ScMessage {
            function: ScFunction::Result,
            message_id: req.message_id.wrapping_add(1),
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x06, 0x01, 0x00, 0x00, 0x07, 0x00, 0x97]),
        };
        let result = decode_sc_bvlc_result(&msg).unwrap();

        assert!(!conn
            .handle_connect_result(msg.message_id, &result, Some(replacement))
            .unwrap());
        assert_eq!(conn.state, ScConnectionState::Disconnected);
        assert_eq!(conn.local_vmac, original);

        let retry = conn.build_connect_request();
        assert_eq!(&retry.payload[0..6], original.as_slice());
    }

    #[test]
    fn handle_connect_result_generic_nak_does_not_replace_vmac() {
        let original = [0x22, 1, 2, 3, 4, 5];
        let mut conn = ScConnection::new(original);
        let req = conn.build_connect_request();
        let replacement = [0x12, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let msg = ScMessage {
            function: ScFunction::Result,
            message_id: req.message_id,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::from_static(&[0x06, 0x01, 0x00, 0x00, 0x07, 0x00, 0x96]),
        };
        let result = decode_sc_bvlc_result(&msg).unwrap();

        assert!(!conn
            .handle_connect_result(req.message_id, &result, Some(replacement))
            .unwrap());
        assert_eq!(conn.state, ScConnectionState::Disconnected);
        assert_eq!(conn.local_vmac, original);
    }

    #[test]
    fn new_with_device_uuid_sends_supplied_uuid() {
        let uuid = [0xAB; 16];
        let mut conn = ScConnection::new_with_device_uuid([1; 6], uuid);
        let req = conn.build_connect_request();

        assert_eq!(&req.payload[6..22], uuid.as_slice());
    }

    #[test]
    fn handle_malformed_bvlc_result_disconnects() {
        let mut conn = ScConnection::new([1; 6]);
        conn.state = ScConnectionState::Connected;

        let msg = ScMessage {
            function: ScFunction::Result,
            message_id: 1,
            originating_vmac: None,
            destination_vmac: None,
            dest_options: Vec::new(),
            data_options: Vec::new(),
            payload: Bytes::new(),
        };
        conn.handle_received(&msg);
        assert_eq!(conn.state, ScConnectionState::Disconnected);
    }

    #[test]
    fn heartbeat() {
        let vmac = [1; 6];
        let hub_vmac = [2; 6];
        let mut conn = ScConnection::new(vmac);
        conn.hub_vmac = Some(hub_vmac);

        let hb = conn.build_heartbeat();
        assert_eq!(hb.function, ScFunction::HeartbeatRequest);
        // AB.2.14.1: no VMACs on HeartbeatRequest
        assert!(hb.originating_vmac.is_none());
        assert!(hb.destination_vmac.is_none());
        assert!(hb.payload.is_empty());
    }

    #[test]
    fn heartbeat_ack() {
        let conn = ScConnection::new([1; 6]);
        let ack = conn.build_heartbeat_ack(42);
        assert_eq!(ack.function, ScFunction::HeartbeatAck);
        assert_eq!(ack.message_id, 42);
        // AB.2.15.1: no VMACs on HeartbeatAck
        assert!(ack.originating_vmac.is_none());
        assert!(ack.destination_vmac.is_none());
        assert!(ack.data_options.is_empty());
        assert!(ack.payload.is_empty());
    }

    #[test]
    fn message_id_wraps() {
        let mut conn = ScConnection::new([1; 6]);
        conn.next_message_id = u16::MAX;
        assert_eq!(conn.next_id(), u16::MAX);
        assert_eq!(conn.next_id(), 0);
        assert_eq!(conn.next_id(), 1);
    }
}
