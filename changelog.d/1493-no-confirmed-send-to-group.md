---
section: Fixed
---
- **Wire:** The confirmed requests the server starts (events, Channel, Command,
  audit) never go to a group address such as a multicast one, and an I-Am from
  one binds nothing. A confirmed event recipient there counts in
  `confirmed_broadcast_recipient`; an unconfirmed one is still sent (#1493).
