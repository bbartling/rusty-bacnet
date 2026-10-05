---
section: Changed
---
- **Breaking (Rust API):** `WhoIsRequest` and `WhoHasRequest` hold one
  `range: Option<DeviceInstanceRange>` in place of their two limits, and the
  client's `who_is`, `who_is_directed`, `who_is_network` and `who_has` take it
  as one argument, so a request with one limit can't be built (#1483).
