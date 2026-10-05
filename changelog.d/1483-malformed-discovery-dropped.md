---
section: Changed
---
- The server drops a Who-Is or Who-Has that doesn't decode before spawning a
  task for it, and counts it in the new `DiscoveryCounters::malformed_dropped`
  (#1483).
