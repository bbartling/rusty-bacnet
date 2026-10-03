---
section: Changed
---
- **Hub-local identity compatibility break (#517):** all four Rust `ScHub`
  startup APIs require a nonzero 16-byte hosting device UUID and reject reserved
  all-zero/all-ff hosting port VMACs before bind at one shared enforcement point.
  `ScHub::start` appends the required UUID argument; other names/order/returns,
  strict TLS, handshake budgets and lifecycle remain. Python `ScHub` adds required
  keyword-only `device_uuid` (owned bytes/bytearray copy); the five positional slots,
  CA-first and VMAC-length diagnostics remain, with identity checks before file I/O.
  Standalone `bacnet-sc-hub` requires `--device-uuid` (32 ASCII hex, no separators),
  with optional `--vmac` retaining `000000000001`. Compose supplies an explicitly
  documented stable TEST-ONLY UUID, not a deployment identity. Callers own
  predeployment generation and durable lifetime storage; exact Connect-Accept
  identities survive tested restarts/recreation. No auto-generation, storage,
  UUID-bit policy, certificate binding, remote-peer admission or node/raw transport
  policy changes. #517 remained open at slice time; no conformance/status promotion.
