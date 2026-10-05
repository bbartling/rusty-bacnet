---
section: Changed
commit: a8450ee759a7ba9bcbec6826fff63596c9dc8cdf
---
- A COV-multiple context keeps up to about four notifications of timestamped
  changes, under a memory ceiling; overflow drops the oldest, never a
  reference's newest or partly sent one, counted in
  `CovCounters::timed_changes_dropped` and warned once per cause (#1039,
  #1163, #1197, #1287, #1357).
