---
section: Fixed
---
- `Priority_Array` is read-only across all 20 first-party commandable object
  families that previously accepted direct property writes (#842). WP, WPM,
  `write_local`, and raw trait writes now deny whole-array and indexed writes,
  including NULL. Command or relinquish through `Present_Value` with a priority;
  indexed array reads and internal priority maintenance remain available.
  Metadata and PICS report read-only access. Refused array writes leave active
  lighting operations untouched, and WPM retains its successful prefix.
