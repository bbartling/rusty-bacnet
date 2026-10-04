---
section: Fixed
---
- **Wire:** The shared endpoint publishes its network's number, so its routed reads naming that
  number, and source Audit records to an address on that network, go as local traffic with no DNET,
  which non-routing peers receive (#1403).
