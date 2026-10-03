---
section: Changed
---
- **Standalone Python static target Audit Reporter (RB-23c, Refs #345):**
  Add pre-start Reporter selection (initially `configure_audit_reporter(instance, *,
  audit_level, auditable_operations, issue_confirmed_notifications)`); unchanged
  `add_audit_reporter()` alone stays inert. The first valid call fixes the Reporter
  identity; repeated calls replace that instance's settings. The plural target
  configuration described above supersedes this singular API and identity rule.
  Initial recipient
  provision now uses the separate Device-owned API described above.
  Strict identifiers, level literals, full-u64 operation masks and actual booleans
  validate before mutation. Configuration freezes at startup ownership transfer,
  including startup in flight and after stop. Existing direct B/IP bindings resolve
  the recipient; an unresolved recipient permits startup and exposes
  CONFIGURATION_ERROR on an enabled Reporter.
  Catch-all/all-priority defaults and existing Rust target sources, bounded delivery,
  health and joined shutdown are reused unchanged. Installed-extension loopback
  tests cover actual public writes, confirmed/unconfirmed receipt/query, suppression,
  invalid-call atomicity and lifecycle behavior. See
  [Python target Reporters](docs/python-api.md#target-audit-reporters).
  This supersedes prior active-Python-Reporter exclusions only for this static
  target-side subset. The Device recipient path above extends its destination
  configuration; ordinary source-side/local-write production, retries/durable
  outbox and full Reporter parity remain outside it. No broader
  Audit/BIBB/BTL/certification, independent interop or #345 closure is claimed.
