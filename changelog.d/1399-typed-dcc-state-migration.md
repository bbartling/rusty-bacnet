---
section: Migration notes
---
- **DCC state (Rust API, #1399):** `BACnetServer::comm_state()` returns
  `bacnet_server::server::DccState`. Compare with `DccState::Enable` or
  `DccState::DisableInitiation`, call `initiation_restricted()`, or take
  `EnableDisable::from(state).to_raw()` where the old 0 or 2 is needed.
  Python's `comm_state()` still returns 0 or 2.
