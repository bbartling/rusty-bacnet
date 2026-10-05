---
section: Migration notes
---
- **DiscoveryCounters (Rust API, #1493):** read it from
  `BACnetServer::discovery_counters()` rather than building one, and end a
  pattern that destructures it with `..`.
