---
section: Fixed
---
- **Breaking (Rust API):** Setters and write paths that store device object
  references, Channel members included, refuse a device identifier that isn't
  a Device object; Python raises `ValueError` (#1285).
