---
section: Changed
---
- **Breaking Rust hub TLS API:** `ScHub::start`, `start_with_uuid`, and
  `start_with_uuid_and_timeouts` now require `ScHubTlsConfig` as their second
  argument, not `TlsAcceptor`. All public hub startup enforces explicit CA trust,
  matching certificate/key, mandatory WebPKI client verification and TLS 1.3-only
  local policy using fixed aws-lc. Raw/custom verifier, provider, protocol-version
  and configuration injection is retired, with no public unchecked escape.
  Names, argument order, return types, zero/custom UUIDs, validated/default
  timeouts and lifecycle remain; `start_with_tls_config` is a compatible alias.
  Retire server-auth-only `sc_latency`/`sc_throughput` benchmark targets and helpers,
  retaining original mTLS targets and clearly historical numeric results. Replace
  the old raw-policy characterization with strict-family runtime and compile-fail
  coverage; WebSocket tests now authenticate before testing WebSocket semantics.
  Python and Docker already use the alias and retain behavior/signatures. Node
  `ClientConfig`/`TlsWebSocket` was left caller-managed by that hub change;
  its subsequent migration is above. No full-profile, UUID fix,
  or performance claim; #513 remains partial, not for public raw hub startup.
  See [Rust migration and limits](docs/rust-api.md#bacnetsc-hub).
