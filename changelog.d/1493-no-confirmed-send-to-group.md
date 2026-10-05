---
section: Fixed
---
- **Wire:** The server sends no confirmed request (event, Channel, Command or
  audit) to a group address such as a multicast one, and binds no device to
  one. A confirmed event recipient there counts in
  `confirmed_broadcast_recipient`, in Python too; an unconfirmed one is still
  sent (#1493).
