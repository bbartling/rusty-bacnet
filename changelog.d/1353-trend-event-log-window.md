---
section: Added
---
- **Wire:** Trend Log and Event Log serve writable Start_Time and Stop_Time
  and keep records only inside that window, logging each opening and
  closing; the server's poller now looks at Event Log windows too (#1353).
