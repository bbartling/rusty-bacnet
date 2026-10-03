---
section: Changed
---
- `bacnet_server::schedule::tick_schedules` drops its unused UTC-offset argument;
  evaluation already used the database clock frame. It only evaluates schedules.
  A running server evaluates them itself and fans COV out for the objects they
  write (#889).
