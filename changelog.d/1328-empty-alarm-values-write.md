---
section: Fixed
---
- **Wire:** WriteProperty and WritePropertyMultiple hand a list property to the
  object as a list at every length, so an empty value clears Alarm_Values; an
  empty write to a read-only or unserved list is now WRITE_ACCESS_DENIED or
  UNKNOWN_PROPERTY, not INVALID_DATA_ENCODING (#1328).
