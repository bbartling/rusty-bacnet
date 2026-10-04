---
section: Fixed
---
- A server stopped mid-request, or a Notification Forwarder, Notification
  Class or Audit Log dropped, while a write was staged for an unfinished
  request now puts storage back to the served state, so a restart no longer
  serves a list no client was told about (#1363).
