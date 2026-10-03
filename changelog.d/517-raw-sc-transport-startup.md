---
section: Changed
---
- **Breaking (Rust API):** `ScTransport::start` requires a nonzero UUID set
  with `with_device_uuid`, and refuses reserved local VMACs (#517).
