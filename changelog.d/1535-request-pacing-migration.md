---
section: Migration notes
---
- **ClientConfig and Error (Rust API, #1535, #1530):** a `ClientConfig`
  literal needs `min_request_interval_ms` (or `..ClientConfig::default()`),
  and an exhaustive match on `Error` needs an arm for `LogNotAdvancing`.
