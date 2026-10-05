---
section: Fixed
---
- **Wire:** B/IP and B/IPv6 drop a Forwarded-NPDU whose originating address is
  a group address, so a forged I-Am can't bind a device to a group, and count
  it in the new `forwarded_group_origin_drops()` (#1493).
