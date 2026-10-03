---
section: Fixed
---
- `BACnetServer::stop()` no longer leaves a Command In_Process TRUE or a Channel IN_PROGRESS: each run it cancels, or that never started, ends as unsuccessful (#1252).
