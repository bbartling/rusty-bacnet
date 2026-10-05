---
section: Changed
---
- An SC node's rejection NAKs must go out within the remaining heartbeat
  budget; a node that misses it retires the socket and recovers only through a
  fresh connection (#519).
