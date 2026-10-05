---
section: Migration notes
---
- **Broadcast sends (Rust API, #1479):** send a remote network's broadcast
  with `NetworkLayer::broadcast_to_network`, not
  `send_apdu_routed_via_local_broadcast` with an empty `dest_mac`. Send a
  confirmed request, an acknowledgement, an Error, a Reject or an Abort to
  one device: the broadcast sends, a routed send with no DADR, and a
  `BACnetClient` confirmed request to the link's broadcast MAC now refuse it
  with `Error::Encoding`.
