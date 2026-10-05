---
section: Added
---
- **Breaking (wire):** Lighting Output carries out its lighting commands:
  fades and ramps move Tracking_Value, steps and STOP act on the priority
  array, and the warn commands (also Present_Value -1.0 to -3.0) act at once,
  or blink and hold for Egress_Time when Blink_Warn_Enable is TRUE (#1384).
