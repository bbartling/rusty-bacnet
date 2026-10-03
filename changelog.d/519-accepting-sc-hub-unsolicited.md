---
section: Changed
---
- **Accepting SC hub unsolicited-response silence (Refs #519):** discard
  Connect-Accept and Disconnect-ACK before activity or state changes, without
  replying, including malformed function-specific fields. Registration, peer
  limits, pending probes and original deadlines remain intact. This is not a
  blanket response filter: Result relay, matching Heartbeat-ACK and all other
  function handling are unchanged. [Scoped evidence and local liveness policy](docs/conformance/standard-135-2020-ledger.md#accepting-hub-unsolicited-response-silence)
  cover Rust and installed-native Python; #519 remains open/partial.
