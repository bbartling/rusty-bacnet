---
section: Fixed
---
- **Wire:** Ethernet counts every multicast MAC, not only the all-ones
  broadcast, as a group destination, so a confirmed request to one is refused;
  `ethernet::is_group_mac` tells them apart (#1493).
