---
section: Migration notes
---
- **Server drop (Rust API, #1270, #1409):** durable saves now finish on a writer thread, so storage
  may still change after a `BACnetServer` dropped without `stop()` is gone. Call `stop().await`
  before dropping a server and building another on the same storage.
