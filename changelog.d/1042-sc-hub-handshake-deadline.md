---
section: Fixed
---
- The SC hub's handshake-deadline tests run on Tokio's paused clock. The
  HTTP-upgrade test waited on real time for the hub's 150 ms budget, so a
  runner stall spanning both the hub's deadline and the test's 300 ms wait
  failed it after the hub had already closed the peer (#1042). The TLS,
  HTTP-upgrade and Connect-wait tests now check each budget 1 ms before and
  1 ms after it ends, and no longer sleep through 10 s and 5 s budgets. The
  B/IP BBMD start tests whose BDT names the bound port before the first start
  probe again with a fresh port when another socket takes the probed one
  before the bind (#1032). The B/IPv6 VMAC-collision test does the same; a
  stolen port used to let it pass without a collision, and it now checks the
  collision error itself.
