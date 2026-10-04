---
section: Fixed
---
- **Wire:** a NULL to a non-commandable property with no NULL in its datatype
  now succeeds unchanged over WP, WPM and local writes, not INVALID_DATA_TYPE.
  A Value_Source correction by a non-owner is WRITE_ACCESS_DENIED even when
  its value is malformed (#1396).
