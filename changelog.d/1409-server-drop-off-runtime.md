---
section: Changed
---
- A `BACnetServer` dropped without `stop()` in async code hands its object database to the
  blocking pool instead of blocking a Tokio worker while durable objects finish saving; call
  `stop()` first to wait for those saves (#1409).
