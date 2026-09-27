//! Socket lifetime and registered-object protection have one destruction order.
use std::{ops::Deref, sync::Arc};
use tokio::net::UdpSocket;

/// Every socket-owning worker retains this same allocation. Rust drops fields
/// in declaration order: the socket closes before the final registration token.
pub(super) struct BipSocket {
    socket: UdpSocket,
    _network_port_lease: Option<Arc<()>>,
}

impl BipSocket {
    pub(super) fn new(socket: UdpSocket, lease: Option<Arc<()>>) -> Self {
        Self {
            socket,
            _network_port_lease: lease,
        }
    }
}

impl Deref for BipSocket {
    type Target = UdpSocket;
    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}
