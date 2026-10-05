---
section: Fixed
---
- **Wire:** timestamped COV-multiple reports carry each change's commit time
  and keep it until delivered, honouring Max_Notification_Delay. An oversized
  report splits in capture order, value by value if need be; a value no
  notification can carry is dropped (#856, #986, #1008, #1090).
