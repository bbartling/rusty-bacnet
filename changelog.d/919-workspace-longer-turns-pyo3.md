---
section: Changed
---
- The workspace no longer turns on pyo3's `extension-module` feature, so
  `cargo nextest run -p rusty-bacnet` links libpython and runs the crate's
  tests (#919).
