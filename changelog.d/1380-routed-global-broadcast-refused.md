---
section: Changed
---
- `NetworkLayer` routed and on-issuance sends refuse destination network 0xFFFF
  with no device address too, pointing to `broadcast_global_apdu`, since a
  unicast global broadcast reaches only one router (#1380).
