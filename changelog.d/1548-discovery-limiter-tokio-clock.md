---
section: Changed
---
- The server's discovery rate limits and coalescing windows read tokio's
  clock, so a paused test runtime steps them like the server's other timers;
  production timing is unchanged, and the discovery tests no longer sleep
  (#1548).
