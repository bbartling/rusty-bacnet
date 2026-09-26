//! BACnet server: APDU dispatch and service handlers.

pub mod audit_notification;
pub mod cov;
mod device_view;
pub mod event_enrollment;
pub mod fault_detection;
pub mod handlers;
pub mod life_safety;
mod life_safety_cov;
mod local_device;
pub mod mutation;
pub mod pics;
pub mod schedule;
pub mod server;
pub mod trend_log;

/// Explicit initiators for local command-source tracking.
pub mod command_source;
pub use command_source::LocalCommandSource;
