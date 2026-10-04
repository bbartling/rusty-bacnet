---
section: Migration notes
---
- **I-Am announcements under DCC (Rust API, #1388):**
  `BACnetServer::broadcast_i_am()` and `IAmBroadcaster::broadcast_i_am()`
  return `Error::Protocol` with `SERVICES` / `COMMUNICATION_DISABLED` while a
  remote DeviceCommunicationControl restricts initiation. An announce loop
  that unwraps the result must treat that error as a skipped announcement.
