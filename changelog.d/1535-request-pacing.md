---
section: Added
---
- **Breaking (Rust API):** `BACnetClient` builders and `ClientConfig` take
  `min_request_interval_ms` (default 0, at most an hour): a request to a
  destination waits that long after the latest one sent there finished, so a
  slow device keeps room for its other clients (#1535).
