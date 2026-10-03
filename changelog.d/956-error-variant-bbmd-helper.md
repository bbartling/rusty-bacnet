---
section: Changed
---
- **Breaking (Rust API):** `Error` gains `UnsupportedTransport`, the client
  BBMD helpers work on any transport that implements `AsBip`, and
  `ScTransport::connection()` and `MstpTransport::node_state()` are private
  (#956).
