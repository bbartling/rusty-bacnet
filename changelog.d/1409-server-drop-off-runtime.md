---
section: Changed
---
- **Breaking (Rust API):** A `BACnetServer` dropped without `stop()` in async code hands its
  object database to the blocking pool instead of blocking a Tokio worker while durable objects
  finish saving, so the drop returns before storage settles (#1409).
