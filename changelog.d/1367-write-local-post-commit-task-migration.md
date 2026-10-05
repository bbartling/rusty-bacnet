---
section: Migration notes
---
- **Local writes (Rust API, #1367):** dropping a `write_local` future after its write committed no longer
  ends the Command or Channel run the write started as failed (#1324): the run goes ahead and reports its
  end. Code that relied on a timeout or `select!` to abandon such a run should not start it, or call
  `stop()`, which still ends it.
