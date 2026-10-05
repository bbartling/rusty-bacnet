---
section: Fixed
---
- A `write_local` dropped after its write committed, by a timeout or a
  `select!`, ends the Command or Channel run it started as if none of its
  writes were made (#1324).
