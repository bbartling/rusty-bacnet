---
section: Changed
commit: 5e9e6763b3224ff7dfc2e19ad7a6c9a132587a3a
---
- **Breaking (Rust API):** `Error` gains `UnsupportedTransport`, the client
  BBMD helpers work on any transport that implements `AsBip`, and
  `ScTransport::connection()` and `MstpTransport::node_state()` are private
  (#956).
