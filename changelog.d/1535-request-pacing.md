---
section: Added
---
- **Breaking (Rust API):** `BACnetClient` builders and `ClientConfig` take
  `min_request_interval_ms` (default 0): a request to a destination waits that
  long after the previous one to it finished, or was sent while still
  outstanding, so a slow device keeps room for its other clients (#1535).
