---
section: Added
---
- `NetworkLayer::local_network_number` is a lock-free handle to the local network number for
  stacks and adapters built directly on `NetworkLayer`; the full server and client fill their own
  layers internally (#1298).
