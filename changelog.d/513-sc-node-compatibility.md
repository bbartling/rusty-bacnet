---
section: Changed
---
- **Breaking (Python API):** `BACnetClient` and `BACnetServer` with
  `transport="sc"` require `sc_ca_cert`, `sc_client_cert` and `sc_client_key`,
  with no fallback to the system roots; see
  [SC configuration](docs/python-api.md#bacnetsc-secure-connect) (#513).
