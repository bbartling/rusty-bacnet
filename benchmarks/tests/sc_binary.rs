//! Standalone executable security regressions with ephemeral loopback peers.
#[path = "sc_binary/handshake.rs"]
mod handshake;
#[path = "sc_binary/peer.rs"]
mod peer;
#[path = "../../crates/bacnet-endpoint/tests/support/port_retry.rs"]
mod port_retry;
#[path = "sc_binary/preflight.rs"]
mod preflight;
#[path = "sc_binary/support.rs"]
mod support;
