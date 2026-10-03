---
section: Changed
---
- The running server's Device read view forwards every read-only
  `BACnetObject` query to the object it wraps, and a test fails when one isn't
  forwarded (#1076).
