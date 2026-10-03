---
section: Changed
---
- **Breaking (Rust and Python API):** a configured server's DCC authorization
  defaults to deny all, even with the right password, until a `DccPolicy` mode
  (Python: `dcc_policy`) is chosen.
