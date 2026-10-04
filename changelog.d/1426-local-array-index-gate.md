---
section: Fixed
---
- **Wire:** `write_local`, a Command's or Channel's local writes and a
  Schedule's target writes refuse an array index on a property that isn't an
  array, as WriteProperty does, instead of letting the object write the whole
  property (#1426).
