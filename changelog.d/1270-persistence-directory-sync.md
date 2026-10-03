---
section: Fixed
---
- The Notification Forwarder's file backend synchronizes its directory after each rename, and the
  Audit Log's when it creates a slot, so a completed save survives a power loss (not on Windows)
  (#1270).
