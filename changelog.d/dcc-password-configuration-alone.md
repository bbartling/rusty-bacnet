---
section: Migration notes
---
- **DCC password (Rust and Python API):** a password alone no longer enables
  DeviceCommunicationControl. Select `RequirePassword` (`"require_password"`)
  with a password, or the **insecure** `LegacyPermissive` mode; exhaustive
  `ServerConfig` literals need `dcc_policy`. See
  [DCC policy](docs/dcc-policy.md).
