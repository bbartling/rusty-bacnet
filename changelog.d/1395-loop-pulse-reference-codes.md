---
section: Changed
---
- **Breaking (Rust API):** A value written directly to a Loop or Pulse
  Converter reference is decoded like a device reference, so a malformed list
  gets the same refusal code and an empty list clears Setpoint_Reference;
  WriteProperty answers are unchanged (#1395).
