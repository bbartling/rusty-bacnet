---
section: Migration notes
---
- **Server drop (Rust API, #1409):** Dropping a `BACnetServer` without `stop()` in async code no
  longer waits for durable objects' last saves, or for the put-back of a write still staged, so
  storage may change after the drop returns. Call `stop().await` before dropping a server and
  building another on the same storage.
