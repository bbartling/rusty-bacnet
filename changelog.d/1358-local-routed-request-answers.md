---
section: Changed
---
- **Wire:** Once the client knows its network's number, `confirmed_request_routed` to that number
  ignores `router_mac` and sends the request straight to the DADR (#1358).
