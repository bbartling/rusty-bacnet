---
section: Changed
---
- **Current-dev SC zero-limit receive compatibility change (Refs #519):**
  Connect-Request and Connect-Accept advertising zero Max-BVLC or Max-NPDU fail
  zero-only local policy after TLS/WebSocket setup. Eligible Requests receive
  `COMMUNICATION/PARAMETER_OUT_OF_RANGE` (7/80); Accepts are silently discarded
  under AB.2, without committing state/identity/limits or resetting the original
  connect deadline. Malformed new Requests close; registered malformed repeats
  retain registration and liveness. All positive values remain compatible,
  including very small and inverted pairs. No universal minimum-capacity
  conformance claim, stronger positive floor or relationship check is added.
  Defaults, independent outgoing budgets, generic zero codec syntax and public
  signatures remain unchanged. [Bounded evidence](docs/conformance/standard-135-2020-ledger.md#received-zero-capacity-admission)
  covers Rust and installed-native Python; #519 stays open/partial. Closed #513
  and #517 acceptance and historical evidence below are not reopened.
