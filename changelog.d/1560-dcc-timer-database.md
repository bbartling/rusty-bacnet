---
section: Fixed
---
- A server dropped while a DeviceCommunicationControl request or the DCC
  timer's expiry held the timer's slot now cancels the timer before letting
  go of the database, so with Audit reporting the timer no longer keeps the
  objects alive until it runs out (#1560).
