//! The two local nonrouter controls for an explicitly opted-in single link.
use bacnet_network::layer::ReceivedNetworkControl;
use bacnet_objects::{database::ObjectDatabase, network_port::NetworkNumber};
use bacnet_types::primitives::ObjectIdentifier;
use std::sync::Arc;
use tokio::sync::RwLock;

enum State {
    Registered(Arc<RwLock<ObjectDatabase>>, ObjectIdentifier),
    Unregistered(NetworkNumber),
}
/// Hidden shared control adapter, not a second configuration or lifecycle API.
#[doc(hidden)]
pub struct NetworkNumberOwner(State);
impl NetworkNumberOwner {
    /// Explicit registration alone provides configured-number authority.
    #[doc(hidden)]
    pub fn new(selected: Option<(Arc<RwLock<ObjectDatabase>>, ObjectIdentifier)>) -> Self {
        Self(match selected {
            Some((db, oid)) => State::Registered(db, oid),
            None => State::Unregistered(NetworkNumber::configured(0)),
        })
    }
    /// Validate and process one control, returning a complete local-control NPDU.
    /// Other network messages retain the owners' existing discard behavior.
    #[doc(hidden)]
    pub async fn handle(&mut self, control: ReceivedNetworkControl) -> Option<Vec<u8>> {
        let npdu = &control.npdu;
        if !npdu.is_network_message || npdu.source.is_some() || npdu.destination.is_some() {
            return None;
        }
        let announcement = match npdu.message_type {
            Some(0x12) if npdu.payload.is_empty() => None,
            Some(0x13) if control.link_layer_group && npdu.payload.len() == 3 => {
                let number = u16::from_be_bytes([npdu.payload[0], npdu.payload[1]]);
                let flag = npdu.payload[2];
                if number == 0 || number == u16::MAX || flag > 1 {
                    return None;
                }
                Some((number, flag))
            }
            _ => return None,
        };
        let state = match &mut self.0 {
            State::Registered(db, oid) => db
                .write()
                .await
                .network_number_internal(*oid, announcement)?,
            State::Unregistered(state) => {
                if let Some((number, flag)) = announcement {
                    state.observe(number, flag);
                }
                *state
            }
        };
        let (number, quality) = state.snapshot();
        if announcement.is_some() || number == 0 {
            return None;
        }
        // Clause 6.4.15: even LEARNED_CONFIGURED is transmitted as learned.
        Some(vec![
            1,
            0x80,
            0x13,
            (number >> 8) as u8,
            number as u8,
            u8::from(quality == 3),
        ])
    }
}
