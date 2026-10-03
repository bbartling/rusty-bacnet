---
section: Changed
---
- Add optional exact claimed-source DCC restriction only with explicit
  `RequirePassword` / `require_password`: absent preserves behavior, empty denies
  all sources, and direct/routed addresses match full bytes. Invalid policy/list
  combinations fail before startup/dial. Rust exhaustive `ServerConfig` literals
  need `dcc_source_restriction: None`; Python adds a keyword-only typed list.
  Addresses (including SC VMAC) remain spoofable, not authenticated principals.
  Existing counters, timer/error precedence and recovery admission are retained;
  [DCC policy](docs/dcc-policy.md) documents the API. #522 remains partial.
