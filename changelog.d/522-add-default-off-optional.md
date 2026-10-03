---
section: Changed
---
- Add a default-OFF optional global DCC DISABLE_INITIATION token bucket per native
  server. Enabled defaults are burst 3 and one token per 20 seconds; authorized
  ENABLE is exempt and earlier validation/authorization failures do not charge.
  Admission charges survive cancellation before commit; denial leaves the timer
  untouched and reuses existing policy-denied telemetry. Rust exposes
  `DccDisableRateLimit` / `dcc_disable_rate_limit` on config and generic/BIP/SC
  builders (exhaustive literals need `None`); Python adds keyword-only
  `dcc_disable_rate_limit=(capacity, refill_interval_ms)` or `None`.
  Python stop/start creates a fresh native bucket, so operator restarts reset it.
  This is not ingress/flood/password-guessing protection or full #522 completion;
  see [DCC policy](docs/dcc-policy.md).
