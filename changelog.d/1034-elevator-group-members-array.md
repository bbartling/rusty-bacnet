---
section: Fixed
---
- **Breaking Elevator Group Group_Members by array index (wire):** a read of
  the Elevator Group's Group_Members with an array index now answers as a
  BACnetARRAY should (#1034). Index 0 is the member count, index n the n-th
  member, and an index past the last member fails with INVALID_ARRAY_INDEX.
  Before, every index returned the whole list.
