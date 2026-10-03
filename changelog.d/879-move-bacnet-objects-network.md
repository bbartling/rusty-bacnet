---
section: Changed
commit: a8194c1425cd192d59cee2ff010a296ff26ad6df
---
- **Breaking (Rust API):** `NetworkNumber` moves from
  `bacnet_objects::network_port` to `bacnet_types::network_number`, and
  `configured` returns `None` for 65535 (#879).
