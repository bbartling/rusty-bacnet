---
section: Fixed
---
- ReadPropertyMultiple responses to a resolved wildcard Device request now
  identify the selected concrete Device in each result wrapper, matching the
  returned Object_Identifier value (#835). Legacy and budgeted server handlers
  agree, including property-error rows; unresolved Device requests retain their
  wildcard identity and UNKNOWN_OBJECT errors.
