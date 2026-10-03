---
section: Migration notes
---
- **Request admission (Rust and Python API):** exhaustive `ServerConfig`
  literals and patterns need the new fields, a small custom global limit needs
  an explicit smaller or zero reserve, and separate ordinary and recovery peer
  quotas replace the confirmed peer ceiling; see
  [request admission](docs/request-admission.md).
