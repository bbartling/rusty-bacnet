---
section: Added
---
- **Rust API:** `BACnetServer` gains `report_access_event_local`,
  `report_credential_read_local` and `report_door_state_local`, which take an
  access event, a reader's read or a door's hardware state as one local write
  that COV and event reporting follow, with each object's out-of-service rule
  (#1132).
