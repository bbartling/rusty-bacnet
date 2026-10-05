---
section: Changed
commit: 3bdf9510caa0dcdca4df8d163cbf0693da196ad4
---
- **Wire:** B/IPv6 with `::` or no interface picks one usable link and
  address, keeps its traffic on that link, and fails startup when the choice
  is ambiguous; it used to ask the routing table for an address and fall back
  to `::1`.
