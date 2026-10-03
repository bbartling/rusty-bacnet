---
section: Changed
---
- **Breaking (Rust and Python API):** `ScServerBuilder` requires
  `device_uuid`, and Python SC clients and servers the keyword
  `sc_device_uuid`; provision one UUID per device and keep it for life (#517).
