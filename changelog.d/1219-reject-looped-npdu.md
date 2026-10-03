---
section: Fixed
---
- **Router rejects for a looped NPDU (wire):** when a refused NPDU's SNET is
  another of the router's networks, the reject goes out that port as a local
  unicast to the SADR; when its SNET/SADR is the router itself, none is sent
  (#1219).
