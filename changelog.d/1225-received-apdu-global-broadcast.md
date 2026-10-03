---
section: Migration notes
---
- `bacnet_network::layer::ReceivedApdu` has a new `global_broadcast` field: code that builds one with a
  struct literal adds `global_broadcast: false`, or `true` for an NPDU sent to DNET 65535 (#1225).
