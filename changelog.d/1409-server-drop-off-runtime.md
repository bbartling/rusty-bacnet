---
section: Changed
---
- **Breaking (Rust API):** durable saves finish on a writer thread, so a `BACnetServer` dropped
  without `stop()` returns before storage settles, and in async code it hands its object database
  to the blocking pool rather than block a Tokio worker (#1270, #1409).
