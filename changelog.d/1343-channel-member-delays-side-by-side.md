---
section: Fixed
---
- A Channel writes each member when its own Execution_Delay is up, so a member
  in another device that waits for its answer no longer delays the others; runs
  send each device one request at a time and at most 32 in all, and Reliability
  names the first failure to finish (#1343).
