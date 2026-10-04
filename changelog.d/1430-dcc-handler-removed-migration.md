---
section: Migration notes
---
- **DCC handler (Rust API, #1430):** `handlers::handle_device_communication_control`
  is removed. Let a `BACnetServer` answer DeviceCommunicationControl under its
  `DccPolicy` and `dcc_password`, and read the state with
  `BACnetServer::comm_state()`, which returns a `DccState`.
