---
section: Migration notes
---
- **DCC state (Python API, #1431):** compare `await server.comm_state()` with
  `EnableDisable.ENABLE` or `EnableDisable.DISABLE_INITIATION`. The result
  never equals 0 or 2 and is truthy in both states, so
  `if await server.comm_state():` no longer tells them apart; `copy`,
  `deepcopy` and `pickle` raise `TypeError` on it. Call `.to_raw()` where the
  number is needed.
