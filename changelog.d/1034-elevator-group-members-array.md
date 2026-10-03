---
section: Fixed
---
- **Breaking (wire):** an array-index read of the Elevator Group's
  Group_Members answers as a BACnetARRAY: index 0 is the member count, and an
  index past the end fails with INVALID_ARRAY_INDEX (#1034).
