---
section: Changed
---
- **Breaking (Rust API):** Building a `BACnetServer` fails when a
  `DeviceBinding`, as the device's own MAC or its router's, is any group
  address of the link, such as a multicast address or the broadcast IP at
  another port, not only its broadcast; the error names the device (#1493).
