---
section: Added
---
- **WriteGroup (wire):** the server executes inbound WriteGroup on its Channels
  and declares it, Channels serve Allow_Group_Delay_Inhibit, and
  `BACnetClient::write_group` (Python too) sends to a device or a broadcast
  (#1151).
