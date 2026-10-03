---
section: Fixed
---
- **Breaking router rejects reach the original source (wire, Rust API):**
  `BACnetRouter` sent every Reject-Message-To-Network as a local unicast to the
  node that handed it the refused NPDU, with no DNET or DADR, so a reject for a
  message relayed by a peer router stopped at that router (#1158). A reject now
  goes to whoever first sent the refused NPDU (Clause 6.4.4).
  - When the refused NPDU carries SNET/SADR, the reject names that node as its
    DNET/DADR, with hop count 255, and goes back out the arrival port to the
    router that relayed the NPDU. Without SNET/SADR it is a local unicast to
    the sender, as before. This covers reasons 1, 2, 3 and 6, which now share
    one send path.
  - A reason 6 reject for an over-long SADR cannot name the originator, so it
    falls back to the local unicast to the sender.
  - A received reject is relayed by its DNET/DADR through the normal routing
    path (Clause 6.6.3.5). The router used to treat the reject's SNET/SADR as
    the originator and send it there; a reject with no DNET now goes no
    further than the router.
  - `NpduDecodeError::AddressTooLong` gains a `source` field: for an
    over-long DADR, the SNET/SADR behind it when the frame holds a complete,
    valid one. Code that matches the variant without `..` must name it.
