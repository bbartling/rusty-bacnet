---
section: Added
---
- **Breaking `CovCounters` (Rust API):** the new
  `CovCounters::untimed_references_oversized` field, with its
  `AtomicCovCounters` twin, counts each time a COV-multiple report leaves out an
  untimestamped reference whose values alone exceed one notification to the
  subscriber (#1066). Until now only a log warning recorded these (#1038). They
  are counted apart from `timed_changes_dropped`, which counts timestamped
  changes lost for good: an untimestamped value has no queue, and the
  reference's next fanout reads it again, so each report that leaves it out
  counts once. The field breaks exhaustive struct literals and patterns.
