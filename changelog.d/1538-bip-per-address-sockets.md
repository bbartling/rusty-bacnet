---
section: Changed
---
- **Wire:** A B/IP transport with an explicit interface address and port binds
  that address, so several devices on one host can share port 47808, each
  getting its own unicast and sending from its own address. Unix adds a
  receive-only broadcast socket ([details](docs/rust-api.md#bip-ipv4), #1538).
