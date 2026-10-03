---
section: Changed
---
- Pre-1.0 WPM request encoding now returns `Result` and validates all writes
  transactionally. Empty outer/nested write lists, special property selectors and
  invalid priorities fail before client admission/discovery. Both Python WPM
  methods validate synchronously; inbound malformed-wire/prefix semantics and
  legal empty-list property values remain unchanged (#793).
