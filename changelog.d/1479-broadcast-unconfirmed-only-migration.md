---
section: Migration notes
---
- **Broadcast sends (Rust API, #1479):** send a remote network's broadcast
  with `NetworkLayer::broadcast_to_network`, not
  `send_apdu_routed_via_local_broadcast` with an empty `dest_mac`. Send a
  confirmed request, an acknowledgement, an Error, a Reject or an Abort to
  one device: the broadcast sends and a routed send with no DADR refuse it,
  and so do confirmed requests from `BACnetClient`, the endpoint and Python
  to any group address, all before anything is sent.
