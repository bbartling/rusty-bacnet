---
section: Fixed
---
- `BACnetServer::stop()` no longer leaves a Command In_Process TRUE or a Channel IN_PROGRESS: each run it cancels, or that never started, ends where it stood, with its unmade writes unsuccessful (#1252).
