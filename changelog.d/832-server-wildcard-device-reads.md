---
section: Fixed
---
- Server wildcard Device reads, live COV lists, discovery and notification
  identity now consistently select the lowest Device instance when the database
  contains multiple Devices (#832). Selection is independent of insertion and
  hash order. Install Devices before startup; changing Device membership later
  does not rebind the discovery limiter's startup identity. Normal single-Device
  behavior and exact-one Audit/Endpoint ownership checks are unchanged.
