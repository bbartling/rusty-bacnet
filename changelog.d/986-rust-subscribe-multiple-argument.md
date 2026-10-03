---
section: Fixed
commit: 9fd2aaf4090f4e4c24086eb287472b82f984a462
---
- **Breaking (Rust API):** timestamped COV-multiple history too large for one
  notification goes out in several instead of being dropped, and
  `subscribe_multiple` takes the subscriber's maximum APDU (#986).
