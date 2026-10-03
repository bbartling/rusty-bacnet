---
section: Added
commit: 5e9e6763b3224ff7dfc2e19ad7a6c9a132587a3a
---
- **Rust API:** `BACnetClient::transport()` borrows a built client's
  transport, so SC link state, B/IP counters and BBMD state, and MS/TP
  diagnostics are reachable after `build()` (#956).
