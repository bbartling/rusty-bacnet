---
section: Changed
---
- **Breaking (Rust and Python API):** alarm and event service types use the
  `bacnet-types` enumerations and bit strings instead of raw integers, with
  the wire encoding unchanged (#914).
