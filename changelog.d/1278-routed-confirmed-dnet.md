---
section: Changed
---
- **Breaking (Rust API):** routed confirmed requests, `add_routed_device` and
  the endpoint requester refuse DNET 0, DNET 65535 and an empty DADR before any
  path or transaction state is taken, instead of sending a request no single
  device can answer (#1278).
