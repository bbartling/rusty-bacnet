---
section: Changed
---
- The workspace no longer turns on pyo3's deprecated `extension-module` feature;
  maturin still enables it for wheels and `maturin develop` through
  `crates/rusty-bacnet/pyproject.toml`. `cargo nextest run -p rusty-bacnet` now
  links libpython, so the crate's 25 lib unit tests, which failed to link on
  undefined Python symbols before, run with its 11 integration tests in CI's
  Python bindings job and in `scripts/ci/local-macos.sh`. Seven of them used
  Python without starting the interpreter and now call `Python::initialize()`
  first. CI installs `libpython3-dev` for the link (#919).
