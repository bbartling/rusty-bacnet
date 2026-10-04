---
section: Migration notes
---
- **DCC handler (Rust API, #1430):**
  `bacnet_server::handlers::handle_device_communication_control` is removed.
  Let a `BACnetServer` answer DeviceCommunicationControl under its `DccPolicy`
  and `dcc_password`, and read the state with `BACnetServer::comm_state()`, a
  `DccState`. A custom dispatcher decodes the request with
  `bacnet_services::device_mgmt::DeviceCommunicationControlRequest::decode`
  and applies its own checks.
