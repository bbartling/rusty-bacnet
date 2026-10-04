---
section: Fixed
---
- **Wire:** a NULL to a non-commandable property with no NULL in its datatype
  now succeeds unchanged as a CreateObject initial value and as a Schedule's
  target write, not INVALID_DATA_TYPE (#1416).
