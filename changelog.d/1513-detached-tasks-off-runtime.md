---
section: Fixed
---
- The tasks a `stop()` leaves to settle staged writes and end runs once the
  application lets go of the database now drop it off the runtime when they
  hold its last handle, as a dropped server's own hand-off does (#1513).
