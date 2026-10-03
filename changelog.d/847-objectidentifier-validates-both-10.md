---
section: Fixed
---
- **Breaking (Rust and Python API):** `ObjectIdentifier` validates its object
  type and instance at construction, and `new_unchecked` is gone (#847).
