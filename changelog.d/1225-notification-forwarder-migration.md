---
section: Migration notes
---
- **ReceivedApdu (Rust API, #1225):** `bacnet_network::layer::ReceivedApdu` has a new
  `global_broadcast` field. Code that builds one with a struct literal adds
  `global_broadcast: false`, or `true` for an NPDU sent to DNET 65535.
