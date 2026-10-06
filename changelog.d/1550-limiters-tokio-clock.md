---
section: Changed
---
- The server's time-synchronization limiter reads tokio's clock, through the
  one helper the discovery, DCC-disable and received-event-log limiters now
  share, so paused tests step its windows exactly; production timing is
  unchanged (#1550).
