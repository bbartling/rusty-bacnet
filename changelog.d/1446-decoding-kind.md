---
section: Changed
---
- **Breaking (Rust API):** `Error::Decoding` carries a `DecodingKind`,
  `Error::InvalidTag` is gone, and `Error::reject_reason` names a request
  decode error's Reject. Server handlers return that error as `Error::Reject`;
  a malformed AtomicReadFile-ACK count is a decoding error (#1446).
