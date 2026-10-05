---
section: Changed
---
- A write that a Notification Forwarder, Notification Class or Access Rights object refuses, or
  a NULL that changes nothing, no longer drops another request's staged save, which then still
  saves once with the database guard released (#1424).
