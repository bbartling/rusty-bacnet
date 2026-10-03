---
section: Fixed
---
- BACnet/SC connections disable Nagle's algorithm, so a small message no
  longer waits on the peer's delayed ACK; the transport tests run more than
  twice as fast on Linux CI (#900).
