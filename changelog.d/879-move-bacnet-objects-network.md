---
section: Changed
---
- Move the pre-1.0 `bacnet_objects::network_port::NetworkNumber` helper directly to `bacnet_types::network_number::NetworkNumber`. `configured` now returns `None` for reserved 65535; default construction is UNKNOWN. Shared nonrouter packet handling lives in `bacnet_network::network_number` (#879).
