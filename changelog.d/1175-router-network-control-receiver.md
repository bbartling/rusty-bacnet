---
section: Added
---
- **Router control receiver (#1175):**
  `RouterOptions::network_control_receiver` adds a `ReceivedNetworkControl`
  receiver for rejects addressed to the router itself, which still update the
  routing table and are no longer relayed.
