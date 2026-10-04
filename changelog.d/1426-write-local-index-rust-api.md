---
section: Changed
---
- **Breaking (Rust API):** `BACnetServer::write_local` returns `Err` for an
  array index on a property that isn't an array or that the object doesn't
  have, where it used to write the property (#1426).
