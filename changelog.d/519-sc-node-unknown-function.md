---
section: Changed
---
- **SC node unknown-function admission (Refs #519):** established node receives
  now reject decoded `0x0D..0xFF` before activity refresh or pending-probe clearing.
  Eligible unicast returns `COMMUNICATION/BVLC_FUNCTION_UNKNOWN` (7/143), original
  function/ID and marker zero, addressed to the valid origin or connection-local
  when absent. All explicit destinations and reserved origins are silent. Unknown
  identity wins option/payload diagnostics as scoped local policy; known functions,
  Result-for-Unknown, handshake, hub and codec behavior remain unchanged. This is
  the fifth path using the existing remaining-activity budget and fresh-only recovery.
  [Wire, real-clock, TLS write-lock and installed-native evidence](docs/conformance/standard-135-2020-ledger.md#node-unknown-function-admission)
  does not promote support or claim full Annex AB; #519 remains open/partial.
