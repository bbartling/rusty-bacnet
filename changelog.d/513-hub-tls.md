---
section: Changed
---
- **Breaking (Rust API):** `ScHub::start` and its variants take an
  `ScHubTlsConfig` instead of a `TlsAcceptor`, enforcing explicit CA trust,
  client verification and TLS 1.3, and the server-auth-only SC benchmarks are
  retired (#513).
