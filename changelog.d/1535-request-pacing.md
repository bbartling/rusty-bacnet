---
section: Added
---
- **Breaking (Rust API):** the client builders and `ClientConfig` take
  `min_request_interval_ms`, a least time between confirmed requests to one
  destination (default 0), so paging or polling a slow device leaves it room
  for its other clients (#1535).
