---
section: Fixed
---
- COV now pairs the selected sample with validated optional Status_Flags (#817).
  Status-only changes bypass numeric thresholds, and property reports include
  present flags once per object. The pre-1.0 table API replaces the sample-only
  field/setter with `CovObservation` and `set_last_notified_observation`.
  Selected or required-companion failure skips the whole observation, including
  ordinary PV failure. Per-context capture preserves lifetime/generation fences,
  completion timing and Life Safety committed-delta behavior.
