---
section: Changed
---
- **SC hub Unknown transit (Refs #519):** registered, addressed Unknown functions
  now relay opaque bytes with the source lease VMAC, no source echo, and encoded
  recipient BVLC limits rather than NPDU limits. Valid Result-for-Unknown ACK/NAK
  replies use the existing guarded return path. Peer-local and pre-registration
  Unknown diagnostics stay on the incoming socket; broadcast/reserved-origin
  rejection is silent and local rejection no longer defers idle probing.
  [Scoped mTLS, lifecycle and native hub-to-node evidence](docs/conformance/standard-135-2020-ledger.md#hub-unknown-transit-and-result-return)
  preserves known-function forwarding and existing deadlines/retirement. #519
  remains open/partial; no support promotion or full Annex AB claim.
