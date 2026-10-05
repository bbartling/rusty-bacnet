---
section: Changed
---
- **Breaking (Rust API):** `Error::Decoding` carries a `DecodingKind`,
  `Error::InvalidTag` is gone, and server handlers return a request's decode
  error as its `Error::Reject`. AtomicReadFile-ACK count, stream and trailing
  faults are decoding errors, not `Error::Reject` (#1446).
