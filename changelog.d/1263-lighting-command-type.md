---
section: Changed
---
- **Breaking (Rust API):** `BACnetLightingCommand` takes a `LightingOperation` and a
  `u8` priority, gains a codec in `bacnet_encoding::constructed`, and Lighting Output
  gains `set_lighting_command` and `lighting_command` (#1263).
