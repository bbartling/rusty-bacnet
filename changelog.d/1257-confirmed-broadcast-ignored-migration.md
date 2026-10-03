---
section: Migration notes
---
- **Server (wire, #1257):** the server no longer answers a confirmed request sent by broadcast or
  multicast. A client that relied on that must address the device directly, by unicast or a routed
  DNET/DADR.
