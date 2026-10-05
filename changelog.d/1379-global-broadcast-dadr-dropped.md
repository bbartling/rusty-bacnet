---
section: Fixed
---
- **Wire:** `NetworkLayer` and `BACnetRouter` drop an inbound NPDU whose DNET
  0xFFFF also carries a DADR and count it in `global_broadcast_dadr_drops()`;
  the router no longer passes such an NPDU on to its other networks (#1379).
