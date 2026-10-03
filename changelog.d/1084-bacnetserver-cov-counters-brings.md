---
section: Added
---
- `BACnetServer.cov_counters()` brings the COV telemetry to Python (#1084).
  It returns a dict with every field of the Rust `CovCounters` under the same
  name, typed by the new `CovCounters` TypedDict in `rusty_bacnet.pyi`, so
  `timed_changes_dropped` and `untimed_references_oversized` are now visible
  from Python too. Like `dcc_outcome_counters()`, it is awaitable and raises
  `RuntimeError` before start and after stop. The binding reads the struct
  through an exhaustive pattern, so a counter added in Rust doesn't compile
  until it reaches Python, and a Rust test checks the stub lists the same
  fields.
