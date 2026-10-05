---
section: Fixed
---
- `BACnetServer::stop()` ends each Command or Channel run it cancels, or that never started, where it stood, with its unmade writes unsuccessful, so none stays In_Process or IN_PROGRESS (#1252).
