---
section: Changed
---
- **SC Hub outcome status (Refs #770, #476):** Rust `ScHubStatus` and Python's
  typed status dictionary include fixed per-start saturating decision counters.
  Actual committed replacement and matching-generation heartbeat removal count;
  canceled/stale work does not. Existing policy, admin/broadcast counts and
  shutdown behavior remain. Real TLS tests cover a Hub restarting on the same
  address/config with established peers and independent counters. This extends
  the unfrozen pre-1.0 status shape; no broader Annex AB support is claimed.
