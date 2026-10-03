---
section: Added
---
- `BACnetClient::transport()` borrows the transport a built client owns, so the
  BACnet/SC connection-state watch and NPDU drop counts, the B/IP management,
  FDT and fanout counters and BBMD state, and the MS/TP diagnostics handle are
  reachable after `build()`, whichever builder made the client. The watch
  receiver, diagnostics handle and BBMD state `Arc` are owned and outlive the
  borrow. The borrow is shared, so it never blocks `stop()`, which stops the
  transport in place. Its rustdoc lists what is supported through it, and that
  sending through the transport or holding the BBMD state lock while the client
  runs is not. The new `bacnet_transport::bip::AsBip` trait lends the
  `BipTransport` beneath a transport: `BipTransport` lends itself, and
  `AnyTransport` lends its `Bip` variant. The new
  `bacnet_types::data_link::DataLink` names a data link (B/IP, B/IPv6, MS/TP,
  SC, Ethernet, loopback) and displays its short name (#956).
