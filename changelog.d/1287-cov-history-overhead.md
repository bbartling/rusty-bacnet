---
section: Changed
---
- The COV-multiple history bound charges each held change's memory overhead to a
  per-context memory ceiling, not the notification room, so a 50-octet
  subscriber whose send fails or is held back keeps four to six small changes
  for later delivery instead of one or two (#1287).
