---
section: Changed
---
- **Python SC node compatibility change:** `BACnetClient` and `BACnetServer`
  with `transport="sc"` now require nonempty `sc_ca_cert`, `sc_client_cert`, and
  `sc_client_key` paths at construction (`ValueError` otherwise). Positional
  layout, `None` defaults for non-SC use, and other transports are unchanged.
  Startup loads explicit site trust and matching operational credentials before
  dialing, with existing `RuntimeError` TLS-config errors and no system-root or
  unauthenticated-client fallback. Server local TLS preflight failures preserve
  registrations for file repair/retry; later failures are not general rollback.
  TLS 1.3-only remains. Caller-owned Rust node TLS configurations are unchanged;
  #513 remains partial. See [SC configuration](docs/python-api.md#bacnetsc-secure-connect).
