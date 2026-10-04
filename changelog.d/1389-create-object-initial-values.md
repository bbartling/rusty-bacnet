---
section: Fixed
---
- **Wire:** CreateObject decodes each initial value as WriteProperty does: a
  list such as Alarm_Values arrives as a list at any length, a scalar with a
  trailing element is INVALID_DATA_TYPE instead of keeping the first, and an
  index on a non-array is PROPERTY_IS_NOT_AN_ARRAY (#1389).
