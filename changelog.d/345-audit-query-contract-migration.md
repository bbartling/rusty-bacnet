---
section: Changed
---
- **Breaking Audit query contract migration (RB-20, Refs #345):** AuditLogQuery
  clients, the retained-storage query runtime, and the typed Python boundary
  now enforce the corrected 2020 baseline end to end (Errata Summary
  2024-04-29 items 7-8). `successful-actions-only` is the three-state
  `BACnetSuccessFilter` integer 0 (all), 1 (successes-only), 2
  (failures-only) — `FAILURES_ONLY` is now really enforced instead of matching
  everything — and `start-at-sequence-number` is an Unsigned64 cursor with a
  literal newest-first continuation. Rust callers must pass
  `BACnetSuccessFilter::{ALL, SUCCESSES_ONLY, FAILURES_ONLY}` (the deprecated
  `from_legacy_bool` helper stays only as an un-wired migration aid) and
  `Option<u64>` cursors. Python callers must pass `successful_actions_only`
  as `0`, `1`, or `2`: the old `True`/`False` now raises `TypeError` (use `1`
  for the old `True`, `0` for the old `False`), out-of-range integers raise
  `ValueError`, and `start_at_sequence_number` accepts the full `0..=2**64-1`
  range. The raw `audit_log_query` escape hatch stays signature- and
  byte-compatible with no validation implication. Storage, receipt-ledger, and
  persisted-schema behavior are unchanged, as are the PICS service names
  (44/45/46). #345 stays open for Audit reporting/forwarding (RB-21/22); no
  Audit Reporting BIBB is claimed.
