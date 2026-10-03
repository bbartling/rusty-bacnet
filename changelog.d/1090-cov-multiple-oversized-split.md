---
section: Changed
---
- **Wire:** a timestamped COV-multiple change too large for one notification
  goes out one value per notification instead of being dropped, so a
  subscriber with a small maximum APDU still gets its changes (#1090).
