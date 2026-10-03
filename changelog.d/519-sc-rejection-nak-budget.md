---
section: Changed
---
- **SC rejection-NAK budget and fresh-only recovery (Refs #519):** node control,
  source and unsupported-MU rejection NAKs now use the remaining accepted-activity
  heartbeat budget, without a new timeout setting. Expiry drops the send future,
  publishes Disconnected and retires that socket from further transport I/O,
  including reconnect/primary restore. Recovery requires a fresh connector or
  unused failover under the existing retry policy; no fresh option means staying
  disconnected. Immediate send errors, wire bytes/silence and other write paths
  are unchanged. Cancellation cannot roll back buffered bytes or already-admitted
  application sends, and retirement is not immediate physical closure.
  [Scoped evidence and runtime limitations](docs/conformance/standard-135-2020-ledger.md#rejection-nak-budget-and-fresh-only-recovery)
  do not claim OS backpressure, hard real-time or full Annex AB conformance. #519 stays open/partial.
