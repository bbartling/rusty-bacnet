---
section: Changed
---
- Audit Log and Notification Forwarder saves run on a writer thread of their own, so a slow disk no
  longer holds the object database lock; a list that can't be saved is still refused, and an Audit
  notification is still stored and acknowledged only once durable (#1270).
