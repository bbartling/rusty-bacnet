---
section: Fixed
---
- BACnet/SC connections disable Nagle's algorithm on hub-accepted, direct-accepted
  and dialed TCP streams (#900). A small message sent before the previous one was
  acknowledged could wait on the peer's delayed ACK: on Linux, the second of two
  back-to-back unicasts through a hub occasionally took about 42 ms, and its
  median was 827 µs. Its worst case is now about 1 ms and its median 631 µs. With
  the SC test clients and hub harness doing the same, the `bacnet-transport` suite
  on the Linux CI runner drops from 115 s to 48 s, and the full CI test run from
  about 110 s to 54 s.
