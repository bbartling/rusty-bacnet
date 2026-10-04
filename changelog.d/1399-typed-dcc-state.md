---
section: Changed
---
- **Breaking (Rust API):** `BACnetServer::comm_state()` returns the new
  `DccState` (`Enable` or `DisableInitiation`) instead of a raw `u8`, since the
  server refuses DISABLE; the unreachable DISABLE request drops are gone
  (#1399).
