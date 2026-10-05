---
section: Changed
---
- **Breaking (Rust API):** `WhoIsRequest` and `WhoHasRequest` hold one
  `range: Option<DeviceInstanceRange>`, which the client's `who_is`,
  `who_is_directed`, `who_is_network` and `who_has` take as one argument, so
  a request can't carry one limit, or send one past instance 4194303 (#1483).
