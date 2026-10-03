---
section: Fixed
---
- The SC hub handshake-deadline tests run on Tokio's paused clock, and the
  B/IP BBMD and B/IPv6 VMAC-collision tests retry with a fresh port when
  another socket takes theirs (#1042, #1032).
