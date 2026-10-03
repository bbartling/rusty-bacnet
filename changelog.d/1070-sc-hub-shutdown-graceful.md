---
section: Changed
---
- Test-only: the SC hub shutdown and graceful-shutdown tests that bind a
  stopped hub's address to prove it closed its listener, and the B/IP
  own-broadcast and ephemeral-port restart tests, run again on fresh ports
  when another socket takes the port between the stop and the bind. A node
  that really keeps its port fails every run. The run limit, lost-port check
  and restart helper that #1070 added to the BBMD tests move to
  `bacnet-transport`'s test-only `port_ownership` code, shared by all of these
  tests. The hub probe binds with SO_REUSEADDR on Unix, so it shows the
  listener closed, not each connection, and on macOS a holder on the wildcard
  address goes unnoticed; that is documented (#1095).
