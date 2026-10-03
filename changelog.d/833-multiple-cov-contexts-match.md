---
section: Fixed
---
- Multiple COV contexts now match the original BACnet client address, process and
  confirmed form independently of the immediate router (#833). Accepted finite
  renewals retarget all retained references; cross-router cancellation preserves
  surviving routes and stale completions cannot advance migrated observations.
  This pre-1.0 Rust API change replaces `MultipleContextKey::endpoint` with
  `recipient: CovRecipient`, adds the explicit route to `subscribe_multiple`,
  and moves the endpoint accessor from the key to subscription data.
