---
section: Changed
---
- **SC Hub operator timing and rate configuration (Refs #769, #476):**
  `ScHubProbePolicy` replaces wall-clock seconds and fixed probe constants with
  one per-Hub monotonic millisecond origin, checked scan/idle/ACK/send settings,
  and skipped missed scans. ACK age remains scan-driven from reservation;
  only matching valid ACKs refresh activity. Rust/Python configure a separate
  transit relay send budget (default five seconds; unified by #774), with existing no-retry,
  no-timeout-retirement semantics. Python also exposes the existing native
  sender/global broadcast-rate policy and counters, validated before file I/O.
  Initiating-node heartbeat bounds and broader Annex AB claims are unchanged.
