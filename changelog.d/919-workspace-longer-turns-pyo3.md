---
section: Changed
commit: e40ea249a7b608478eab2a325c20f9a31a13be4e
---
- The workspace no longer turns on pyo3's `extension-module` feature, so
  `cargo nextest run -p rusty-bacnet` links libpython and runs the crate's
  tests (#919).
