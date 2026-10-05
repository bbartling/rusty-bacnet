---
section: Migration notes
---
- **Breaking:** `BACnetRouter::start` takes a `RouterOptions` and returns a
  `StartedRouter` (#1220). Replace `start(ports)` with
  `start(ports, RouterOptions::new())` and take `router` and `apdus` from the
  result.
