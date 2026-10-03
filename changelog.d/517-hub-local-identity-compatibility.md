---
section: Changed
---
- **Breaking (Rust and Python API):** every SC hub startup API requires a
  nonzero hosting device UUID (`device_uuid` in Python, `--device-uuid` for
  `bacnet-sc-hub`) and refuses reserved hub VMACs (#517).
