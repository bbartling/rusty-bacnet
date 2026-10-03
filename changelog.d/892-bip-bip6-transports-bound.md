---
section: Fixed
---
- B/IP and B/IPv6 transports bound to port 0 no longer set `SO_REUSEADDR` (#892).
  On Linux the kernel could give such a socket an ephemeral port that another
  `SO_REUSEADDR` socket already held. Unicast to that port then reached only one
  of them, so replies and notifications for the other were silently lost,
  including across processes. The choice is made when the transport is
  constructed, so a restart that rebinds the remembered actual port keeps it
  private. An explicit port such as 47808 still sets it, as before. It caused
  the intermittent audit-delivery test timeouts on Linux CI.
