---
section: Fixed
---
- **Breaking (wire, Rust API):** a configured recipient's MAC is at most 18
  octets, routing holds every Notification Class to the 32-destination cap,
  and the flat Recipient_List form from before #152 is gone (#1098, #1124,
  #1125).
