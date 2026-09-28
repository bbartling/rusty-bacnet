//! The two local nonrouter controls for an explicitly opted-in single link.
use bacnet_network::layer::ReceivedNetworkControl;
use bacnet_network::network_number::{number_is_reply, NumberControl};
use bacnet_objects::database::ObjectDatabase;
use bacnet_types::network_number::NetworkNumber;
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
            None => State::Unregistered(NetworkNumber::default()),
        })
    }
    /// Validate and process one control, returning a complete local-control NPDU.
    /// Other network messages retain the owners' existing discard behavior.
    #[doc(hidden)]
    pub async fn handle(&mut self, control: ReceivedNetworkControl) -> Option<Vec<u8>> {
        let announcement = match NumberControl::parse(&control)? {
            NumberControl::WhatIs => None,
            NumberControl::NumberIs { number, flag } => Some((number, flag)),
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
        if announcement.is_some() {
            return None;
        }
        number_is_reply(state).map(|npdu| npdu.to_vec())
    }
}
