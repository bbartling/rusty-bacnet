---
section: Changed
commit: ca35afcde79727fce0176fc562e280d93134904d
---
- **Breaking (Rust API):** the `bacnet-objects` event detectors and enrollment
  objects hold typed transitions, notify types and reliabilities, and the
  duplicate `bacnet_objects::event::LimitEnable` is gone (#914).
