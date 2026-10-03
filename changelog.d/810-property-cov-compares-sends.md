---
section: Fixed
---
- Property COV now compares and sends one typed selected-value sample (#810),
  without Present_Value fallback on a failed read. Numeric, count, nullable-slot
  and reviewed structured/whole-array profiles have explicit comparison rules;
  unclassified whole arrays are refused independently of increment presence.
  Validated immutable samples cap retained depth/nodes/payload bytes and share
  normalized storage across accepted snapshots. This pre-1.0 API change replaces
  the float baseline with `CovSample` and `set_last_notified_sample`; all callers
  migrate directly. Existing lifetime/generation fences and ordinary-object and
  Life Safety status triggers remain in force.
