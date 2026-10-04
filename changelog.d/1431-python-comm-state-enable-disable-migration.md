---
section: Migration notes
---
- **DCC state (Python API, #1431):** compare `await server.comm_state()` with
  `EnableDisable.ENABLE` or `EnableDisable.DISABLE_INITIATION`. The result no
  longer equals 0 or 2, so an `int` comparison never matches; call `.to_raw()`
  where the number is needed.
