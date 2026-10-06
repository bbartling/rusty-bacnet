---
section: Fixed
---
- **Wire:** `BACnetRouter` delivers only an Unconfirmed-Request to a DADR that
  is a group address on its delivery port, and counts any other in the new
  `group_dadr_drops()` (#1504).
