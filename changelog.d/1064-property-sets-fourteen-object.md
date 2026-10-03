---
section: Fixed
commit: 8a748c258277400eff1029183fbffbff57cbd321
---
- **Breaking (wire):** fourteen object types drop properties their Clause 12
  tables don't define, such as Out_Of_Service on Command and Notification
  Class; reading one now fails with UNKNOWN_PROPERTY (#1064).
