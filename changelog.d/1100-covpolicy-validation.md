---
section: Added
---
- **Breaking `CovPolicy` validation (Rust API):** Python servers can now set
  their COV limits with a keyword-only `cov_policy` dict on `BACnetServer`
  (#1100). Before, they always ran `CovPolicy::default()`. Each key is a
  `CovPolicy` field under its Rust name: the global and per-peer subscription
  caps, the reserved capacity and the peers that may use it, the indefinite
  lifetime switch and quota, the per-event notification and byte budgets, and
  the confirmed in-flight limit. A key left out keeps its default, typed by the
  new `CovPolicy` TypedDict in `rusty_bacnet.pyi`. The new
  `CovPolicy::validate` refuses a zero subscription cap, notification budget or
  in-flight limit, and a reserved peer that no request could match: a MAC
  outside 1 to 255 octets, or a routed network outside 1 to 65534. The Rust
  server now runs it before starting a transport, as it does the request
  budgets, so a Rust server configured with one of these values fails to start
  where it used to run refusing all COV work. Python runs the same check at
  construction: an unknown key or a value of the wrong type raises TypeError, a
  negative or oversized integer OverflowError, and a refused value ValueError,
  as the other constructor keywords do. The conversion names every field
  without `..`, so a field added in Rust doesn't compile until Python can set
  it.
