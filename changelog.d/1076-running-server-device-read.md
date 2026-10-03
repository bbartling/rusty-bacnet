---
section: Changed
commit: 436dd01dd5ff577d5cccf2a15e0ca91639969a94
---
- The running server's Device read view forwards every read-only
  `BACnetObject` query to the object it wraps, and a test fails when one isn't
  forwarded (#1076).
