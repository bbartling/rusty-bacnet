---
section: Changed
---
- **Rust and Python API:** multi-device RP, RPM and WP batch limits take
  `Option<NonZeroUsize>` in Rust, and Python refuses zero with `ValueError`;
  `None` still means 32.
