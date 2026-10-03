---
section: Fixed
---
- On Windows, a B/IP transport bound to `0.0.0.0` now lists the host's IPv4
  addresses with `GetAdaptersAddresses`, as Linux and macOS do with
  `getifaddrs`, and accepts a unicast datagram only when its destination is
  one of them, as they do (#952). Before, it had no list and accepted any
  datagram that Windows flagged as unicast. A wildcard BBMD finds its own BDT
  row in the same list, by the same rules on every platform (#937). The list
  is read at each `start()`, so an address added later is accepted after the
  next restart. It holds every address configured on the host, on any
  interface, up or down, loopback and link-local included. On Windows that is
  every address except those duplicate address detection marked as duplicate
  (in use by another host) or invalid; a tentative one, as Windows reports a
  static address on a disconnected adapter, counts. The listing runs on a
  blocking thread. A `0.0.0.0` `start()` now fails on every platform when the
  addresses cannot be listed, with the OS error's kind, or when none is
  usable, and the error suggests binding an explicit interface address.
