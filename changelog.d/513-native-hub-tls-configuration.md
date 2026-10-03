---
section: Changed
---
- **Native hub TLS configuration (initially opt-in, now required above):** `ScHubTlsConfig::from_der` validates
  explicitly supplied, already loaded CA/chain/key DER without I/O, builds
  mandatory client verification and TLS 1.3-only local policy, and exposes no raw
  or mutable policy escape. `ScHub::start_with_tls_config` accepts caller UUID and
  validated handshake timeouts while reusing the existing lifecycle. Python hub
  startup delegates to this factory; its constructor, errors and file-loading
  boundary stay compatible. The initial additive change left raw `TlsAcceptor`
  startup APIs unchanged; their retirement is described above. That initial change
  did not migrate node TLS APIs; the subsequent source break is above. Docker's separate
  standalone migration is described above. Native
  preflight, compile-fail, real TLS/SC relay/deadline and installed Python tests
  cover this partial migration, not full-profile conformance or #513 closure.
  See [native hub configuration and limits](docs/rust-api.md#bacnetsc-hub).
