---
section: Fixed
---
- **Wire:** `write_local`, Command and Channel local writes and Schedule
  target writes refuse an array index as WriteProperty does
  (PROPERTY_IS_NOT_AN_ARRAY, or UNKNOWN_PROPERTY) instead of writing the
  whole property; a Schedule's NULL to such a reference now fails (#1426).
