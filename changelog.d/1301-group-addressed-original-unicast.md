---
section: Changed
---
- B/IP and B/IPv6 take an Original-Unicast-NPDU's group-delivery flag from the address it was
  sent to, so the server never answers a confirmed request sent to a broadcast address or multicast
  group, even if the BVLL destination check that drops one were relaxed (#1301).
