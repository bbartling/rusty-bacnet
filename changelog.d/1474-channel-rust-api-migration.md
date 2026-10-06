---
section: Migration notes
---
- **Channel values (Rust API, #1474):** give `MemberDatatype::of` the
  member's object type first, and match its new `ColorCommand` and `XyColor`.
  Replace `is_lighting_command_channel_value(octets)` with
  `constructed_channel_value(octets) == Some(ConstructedChannelValue::LightingCommand)`.
