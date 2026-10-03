---
section: Fixed
---
- Target Audit now supports 1–64 configured Reporters with lowest-instance nominal
  election, overlap health, independent loss contexts and one global admission budget.
  Live Rust Reporter configuration and Description changes share atomic capture.
  Pre-1.0 API replacement: `AuditReportersConfig { reporters }`, `.audit_reporters(...)`,
  and Python `configure_audit_reporters([...])`; singular selectors are removed.
  Source reporting remains exactly one; no full Audit conformance claim (#782).
