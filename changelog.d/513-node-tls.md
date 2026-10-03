---
section: Changed
---
- **Breaking Rust node TLS API:** `TlsWebSocket::connect`,
  `ScClientBuilder::tls_config`, and `ScServerBuilder::tls_config` require opaque
  `ScNodeTlsConfig` rather than `Arc<rustls::ClientConfig>`. Construct from owned
  CA/chain/key DER: explicit nonempty trust, all-entry syntax checks, matching
  operational key, fixed aws-lc, normal server CA/name verification and TLS 1.3-only
  local policy, before I/O. No raw/mutable escape. Clones and reconnects share the
  same configuration and normal resumption cache; tickets/early-data policy remain.
  This local contract supplies identity when requested and compatible, not proof
  of presentation on every connection or remote hub verification. Trusted servers
  without CertificateRequest can complete; resumption may not retransmit certs.
  Generic custom WebSocket transports remain outside the built-in driver guarantee.
  Python/CLI interfaces, file/error phases, Docker provisioning and hub policy stay
  compatible. No local date/issuer/EKU/authorization preflight or full-profile claim;
  #513 stays open pending final acceptance assessment. See the
  [migration and limits](docs/rust-api.md#strict-local-node-tls-configuration).
