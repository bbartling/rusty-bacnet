---
section: Fixed
---
- A `write_local` dropped after its write committed, by a timeout or a
  `select!`, no longer leaves the Command or Channel it started busy until
  `stop()`: the run ends as if none of its writes were made (#1324).
