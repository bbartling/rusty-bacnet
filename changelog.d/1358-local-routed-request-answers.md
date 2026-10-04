---
section: Changed
---
- **Wire:** Once the client knows its network's number, `confirmed_request_routed` to that number
  ignores `router_mac`, and only an answer from the DADR completes the request; one relayed back
  with that number as its SNET goes unmatched (#1358).
