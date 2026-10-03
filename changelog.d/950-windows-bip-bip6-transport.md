---
section: Fixed
commit: 7abb5e451793bca30c923e2244e6bba93efea336
---
- On Windows, a B/IP or B/IPv6 transport on an ephemeral port sets
  SO_EXCLUSIVEADDRUSE, so another socket can't take its unicast (#950).
