---
section: Migration notes
---
- **Breaking:** `BACnetRouter::start` takes a `RouterOptions` and returns a
  `StartedRouter` (#1220). Replace `start(ports)` with
  `start(ports, RouterOptions::new())` and take `router` and `apdus` from the
  result. The other start constructors are gone: use `track_admission()`,
  `control_policy()`, `control_authorizer()` and `network_control_receiver()`.
