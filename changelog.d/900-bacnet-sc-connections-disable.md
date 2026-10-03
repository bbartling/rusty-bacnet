---
section: Fixed
commit: 1b9955044bfb2876af3e6994283555169d43b6b8
---
- BACnet/SC connections disable Nagle's algorithm, so a small message no
  longer waits on the peer's delayed ACK; the transport tests run more than
  twice as fast on Linux CI (#900).
