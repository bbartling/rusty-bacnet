---
section: Fixed
---
- Command runs no longer leave In_Process stuck TRUE away from the bundled server: `tick_schedules` runs the lists it starts, and the bare write handlers end the runs they can't make as unsuccessful (#1178).
