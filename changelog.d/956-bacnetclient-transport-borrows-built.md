---
section: Added
---
- **Rust API:** `BACnetClient::transport()` borrows a built client's
  transport, so SC link state, B/IP counters and BBMD state, and MS/TP
  diagnostics are reachable after `build()` (#956).
