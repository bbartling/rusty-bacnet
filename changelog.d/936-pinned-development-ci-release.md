---
section: Changed
---
- The pinned development, CI and release toolchain moves from Rust 1.97.1 to
  1.99.0 (`rust-toolchain.toml`, the CI image, which also takes rustup 1.29.1,
  the Docker example and the docs); the MSRV stays 1.93. Clippy 1.99's new
  `chunks_exact_to_as_chunks` lint moves ten constant-size `chunks_exact` loops
  to `as_chunks`, whose fixed-size chunks also drop a `try_into().unwrap()` from
  UCS-4 validation. Rust 1.99 deprecates the atomics' `fetch_update` in favour of
  `try_update`, which needs Rust 1.95, so the ten counters that use it keep
  `fetch_update` with a scoped `allow(deprecated)` until the MSRV reaches 1.95
  (#936).
