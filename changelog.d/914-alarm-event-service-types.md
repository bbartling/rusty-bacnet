---
section: Changed
commit: ca35afcde79727fce0176fc562e280d93134904d
---
- **Breaking (Rust and Python API):** alarm and event service types use the
  `bacnet-types` enumerations and bit strings instead of raw integers, with
  the wire encoding unchanged (#914).
