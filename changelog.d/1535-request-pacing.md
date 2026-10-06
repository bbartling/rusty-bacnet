---
section: Added
---
- **Breaking (Rust API):** `BACnetClient` builders and `ClientConfig` take
  `min_request_interval_ms` (default 0, at most an hour): requests to a
  destination take turns, each waiting that long after the one before
  finished, so a slow device keeps room for its other clients (#1535).
