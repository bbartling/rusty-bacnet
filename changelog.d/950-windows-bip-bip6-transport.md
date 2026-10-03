---
section: Fixed
---
- On Windows, a B/IP or B/IPv6 transport on an ephemeral port sets
  SO_EXCLUSIVEADDRUSE, so another socket can't take its unicast (#950).
