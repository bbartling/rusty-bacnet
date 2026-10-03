---
section: Fixed
---
- **Breaking (Rust API):** timestamped COV-multiple history too large for one
  notification goes out in several instead of being dropped, and
  `subscribe_multiple` takes the subscriber's maximum APDU (#986).
