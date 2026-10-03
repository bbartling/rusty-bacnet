---
section: Added
---
- **Loopback unicast destinations (#1243):**
  `LoopbackTransport::record_unicast_destinations` reports the MAC each
  unicast was sent to, in the order the peer receives the frames, so tests
  can check where a unicast went.
