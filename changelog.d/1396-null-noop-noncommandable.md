---
section: Fixed
---
- **Wire:** a NULL written to a property that isn't commandable and has no NULL
  in its datatype now succeeds and leaves it unchanged, over WriteProperty,
  WritePropertyMultiple and local writes, instead of INVALID_DATA_TYPE (#1396).
