---
section: Changed
---
- **SC hub Address-Resolution transit (Refs #519):** registered unicast Request
  `0x02` and ACK `0x03` now preserve opaque bytes, stamp the source lease VMAC,
  remove the destination, and obey encoded BVLC limits, not NPDU limits. Empty
  ACK URI lists relay; broadcasts and nonforwardable ACKs are silent. Eligible
  peer-local/pre-registration Requests retain same-socket 7/150 without activity.
  Only Result-for-Request joins the guarded return path; Result-for-ACK stays
  dropped. [Scoped wire, lifecycle and installed-native hub evidence](docs/conformance/standard-135-2020-ledger.md#hub-address-resolution-transit)
  preserves deadlines/retirement and NODE behavior. No URI parser, direct
  connections, general known-function forwarding or support promotion; #519
  remains open/partial, not full Annex AB support.
