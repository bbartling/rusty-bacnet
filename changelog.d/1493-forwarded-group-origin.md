---
section: Fixed
---
- **Wire:** B/IP drops a Forwarded-NPDU whose originating address is a group
  address, so a forged I-Am can't bind a device to a group. B/IP and B/IPv6,
  which already dropped multicast origins, count such drops in the new
  `forwarded_group_origin_drops()` (#1493).
