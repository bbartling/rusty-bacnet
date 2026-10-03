---
section: Fixed
commit: 9d4baf4b1146ec70f5958285cf1d1b7ddc64abc4
---
- The SC hub handshake-deadline tests run on Tokio's paused clock, and the
  B/IP BBMD and B/IPv6 VMAC-collision tests retry with a fresh port when
  another socket takes theirs (#1042, #1032).
