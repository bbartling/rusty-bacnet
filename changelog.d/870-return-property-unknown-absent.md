---
section: Fixed
---
- Return `PROPERTY/UNKNOWN_PROPERTY` for absent unindexed properties at built-in
  object write fallbacks, including NULL values, unprovisioned Staging names and absent stream File
  `RECORD_COUNT`.
  Present read-only properties still deny writes; earlier state/source/security
  and indexed guards, plus WPM successful-prefix behavior, remain intact (#870).
