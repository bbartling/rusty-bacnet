---
section: Changed
---
- Multi-device RP/RPM/WP batch limits now use `Option<NonZeroUsize>` in Rust.
  Python rejects zero synchronously with `ValueError`, including empty batches.
  `None` still selects 32; result shapes and completion order are unchanged.
