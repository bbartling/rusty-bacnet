---
section: Changed
---
- CI builds the Python bindings with maturin and runs their unittest suite on
  every PR, so a binding break no longer waits for a local run or a release.
  Cargo Deny now checks the bindings' dependencies as well, and the
  `rusty-bacnet` crate declares its MIT licence in `Cargo.toml` (#903).
