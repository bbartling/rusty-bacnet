---
section: Changed
---
- **Breaking (Rust API, Python API):** `CovPolicy` and the Python `cov_policy`
  keyword refuse a reserved peer or recipient MAC longer than 18 octets, which
  could never match a subscriber; they accepted up to 255 (#1199).
