---
section: Fixed
---
- **Wire:** a confirmed event notification whose Device recipient's observed binding expires before a
  retry now ends at that retry and frees its invoke ID, counted in `device_recipient_unbound` (#1371).
