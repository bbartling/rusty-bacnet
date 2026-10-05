---
section: Changed
---
- Durable saves run on a writer thread of their own, so a slow disk no longer holds the object
  database lock; a list that can't be saved is still refused, an Audit notification is acknowledged
  only once durable, and `stop()` waits for queued saves (#1270, #1363).
