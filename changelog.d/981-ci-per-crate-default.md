---
section: Changed
---
- CI's per-crate default-features check (clippy and rustdoc for each published
  crate on its own, plus `no_std` `bacnet-types`) now runs for Windows
  (`x86_64-pc-windows-msvc`) and macOS (`aarch64-apple-darwin`) as well as
  Linux, cross-checked on the Linux runner, so code and docs behind a platform
  `cfg` are checked with default features too. `scripts/ci/check-default-features.sh`
  takes target triples, and one cargo run per crate checks them side by side,
  which adds seconds rather than a minute per target (#981). Before it builds,
  the native Windows job disables and stops the Inventory and Compatibility
  Appraisal service (`InventorySvc`), which started the Compatibility
  Appraiser's `CompatTelRunner.exe` several times a job, and any running copy
  of it. Its bursts on every CPU could blow a test's timing budget (#1003).
