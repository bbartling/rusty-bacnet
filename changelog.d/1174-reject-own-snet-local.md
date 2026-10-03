---
section: Fixed
---
- **Router rejects for a node on the arrival link (wire):** when a refused
  NPDU's SNET is the arrival port's own network, `BACnetRouter` now sends the
  reject as a local unicast to its SADR instead of addressing it with a DNET
  that a non-router discards (#1174).
