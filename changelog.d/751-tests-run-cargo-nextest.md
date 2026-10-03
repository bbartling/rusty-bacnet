---
section: Changed
---
- Tests run with cargo-nextest: CI, the release gate and
  `scripts/ci/local-macos.sh` use `cargo nextest run` (one process per test),
  plus `cargo test --doc` for doctests, which nextest skips. `.config/nextest.toml`
  recommends 0.9.145 or later, stops a test hung past two minutes as a timeout
  failure, and gives CI a no-fail-fast `ci` profile. Older nextest on macOS
  flagged unrelated passing tests as leaky (#751).
