---
section: Fixed
---
- Add direct B/IP endpoint WriteProperty through the shared requester and source
  Audit owner (#852). Rust requires `Commandability`; Python requires the keyword
  `commandability="commandable"` or `"noncommandable"` and returns `Awaitable[None]`.
  Source WRITE records preserve complete 0–32-byte values, one Invoke ID across
  retries, and session ownership after eligible admission. Shared hidden execution
  types and source-owner names are now operation-neutral; RP/RR/RPM stay unchanged.
