---
section: Changed
---
- **Breaking (Python API):** `ScHub` requires an explicit `ca_cert` and always
  verifies clients over TLS 1.3, with no one-way TLS default; see
  [ScHub](docs/python-api.md#schub) (#513).
