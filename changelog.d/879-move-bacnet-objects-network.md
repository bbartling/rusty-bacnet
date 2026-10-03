---
section: Changed
---
- **Breaking (Rust API):** `NetworkNumber` moves from
  `bacnet_objects::network_port` to `bacnet_types::network_number`, and
  `configured` returns `None` for 65535 (#879).
