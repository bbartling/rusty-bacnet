---
section: Added
---
- **Loopback data attributes (#1289):** `LoopbackTransport::carry_data_attributes`
  hands the peer the data attributes each frame is sent with, so tests can
  check the attributes a router sends back. By default they are still dropped.
