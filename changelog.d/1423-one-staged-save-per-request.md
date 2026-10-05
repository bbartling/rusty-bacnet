---
section: Changed
---
- A WritePropertyMultiple's several writes to one Notification Forwarder, Notification Class
  or Access Rights object stage one save, made with the database guard released, instead of
  saving every write after the first in place under the guard (#1423).
