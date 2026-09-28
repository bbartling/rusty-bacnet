//! Shared packet contract for the two local nonrouter Network Number controls.
use crate::layer::ReceivedNetworkControl;
use bacnet_types::{enums::NetworkMessageType, network_number::NetworkNumber};

/// A validated local control, independent of transport and configured authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberControl {
    /// A local query received by unicast or logical broadcast.
    WhatIs,
    /// A valid logical-broadcast announcement.
    NumberIs {
        /// Peer-reported number, in 1..=65534.
        number: u16,
        /// Peer-reported configured flag, zero or one.
        flag: u8,
    },
}
impl NumberControl {
    /// Refuse routed, malformed or ineligible controls without changing state.
    pub fn parse(control: &ReceivedNetworkControl) -> Option<Self> {
        let npdu = &control.npdu;
        if !npdu.is_network_message || npdu.source.is_some() || npdu.destination.is_some() {
            return None;
        }
        match npdu.message_type {
            Some(t)
                if t == NetworkMessageType::WHAT_IS_NETWORK_NUMBER.to_raw()
                    && npdu.payload.is_empty() =>
            {
                Some(Self::WhatIs)
            }
            Some(t)
                if t == NetworkMessageType::NETWORK_NUMBER_IS.to_raw()
                    && control.link_layer_group
                    && npdu.payload.len() == 3 =>
            {
                let number = u16::from_be_bytes([npdu.payload[0], npdu.payload[1]]);
                let flag = npdu.payload[2];
                (number != 0 && number != u16::MAX && flag <= 1)
                    .then_some(Self::NumberIs { number, flag })
            }
            _ => None,
        }
    }
}

/// Encode a known number as a complete local-broadcast control NPDU.
/// Learned-configured state still transmits flag zero; unknown has no reply.
pub fn number_is_reply(state: NetworkNumber) -> Option<[u8; 6]> {
    let (number, quality) = state.snapshot();
    (number != 0).then_some([
        1,
        0x80,
        NetworkMessageType::NETWORK_NUMBER_IS.to_raw(),
        (number >> 8) as u8,
        number as u8,
        u8::from(quality == 3),
    ])
}

#[cfg(test)]
mod tests;
