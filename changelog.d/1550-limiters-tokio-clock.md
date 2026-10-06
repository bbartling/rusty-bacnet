---
section: Changed
---
- The server's time-synchronization limiter now reads tokio's clock, like the
  discovery, DCC-disable and received-event-log limiters, through one helper
  the four share, so paused tests step their windows exactly; production
  timing is unchanged (#1550).
