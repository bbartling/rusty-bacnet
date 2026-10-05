---
section: Migration notes
---
- `CanonicalPeer::from_source` takes the known local network number as a third
  argument (`None` keeps the old matching), and
  `NotificationTransactions::admit_terminal` and
  `ServerRoleHandle::admit_notification_terminal` take it before the APDU
  (#1465).
