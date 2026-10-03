---
section: Fixed
---
- COV subscription identity now distinguishes exact transport/routed endpoints,
  ordinary/Single/Multiple families, optional array indexes and Multiple confirmed
  forms (#812). Table admission returns immutable accepted snapshots and checks
  quota plus nonwrapping generation capacity before publishing replacements;
  old initial/fanout completion cannot overwrite a renewal or recreated entry.
  Public table lookup/cancellation now use typed keys, and baseline completion
  takes an accepted snapshot. Exact endpoint cleanup preserves other routers'
  subscriptions while quota grouping remains shared. This pre-1.0 API change
  does not add delayed Multiple delivery or new property threshold behavior.
