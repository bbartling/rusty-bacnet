---
section: Changed
---
- **Breaking (Rust API):** `TlsWebSocket::connect` and the SC client and
  server builders' `tls_config` take an opaque `ScNodeTlsConfig` built from
  CA, chain and key DER instead of a rustls `ClientConfig` (#513).
