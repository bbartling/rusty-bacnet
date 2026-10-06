---
section: Added
---
- **Rust and Python API:** `share_port_by_address` lets a B/IP device bind its
  interface address, so devices on one host share a port. It then sends from
  that address, gets broadcasts and unicast in no fixed order, and on Windows
  claims the address ([details](docs/rust-api.md#sharing-a-port-by-address), #1538).
