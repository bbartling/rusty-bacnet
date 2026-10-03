---
section: Fixed
---
- **Breaking Rust API:** `ScHub::start`, and every other hub start method,
  now returns `Error::Transport` with the OS's `io::Error` when it can't bind
  its listen address or read the bound address back, as the B/IP transports
  do (#1104). Before, it returned `Error::Encoding` with the error's text, so
  a caller had to match the message to tell an address in use from other
  failures; now `ErrorKind::AddrInUse` says so. The `bacnet-sc-hub` benchmark
  binary names the listen address and the error kind when its bind fails, and
  the benchmarks hub-restart test reads that kind to spot a port another
  process took. Test-only: the SC hub test that restarts on its first port
  runs again from a fresh port when another socket takes that port while no
  hub holds it, like the other hub restart and release tests (#1095).
