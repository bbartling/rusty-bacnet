---
section: Migration notes
---
- **SC TLS (Rust API, #513):** build hub TLS with `ScHubTlsConfig::from_der`
  for `ScHub::start`, and node TLS with `ScNodeTlsConfig` for
  `TlsWebSocket::connect` and the builders' `tls_config`, from owned CA, chain
  and key DER. See the [hub](docs/rust-api.md#bacnetsc-hub) and
  [node](docs/rust-api.md#strict-local-node-tls-configuration) migration
  notes.
