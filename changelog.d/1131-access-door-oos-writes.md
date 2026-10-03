---
section: Fixed
---
- **Breaking (wire):** an Access Door accepts Door_Status, Lock_Status and
  Door_Alarm_State writes while Out_Of_Service is TRUE, so a client can
  simulate the door (#1131).
