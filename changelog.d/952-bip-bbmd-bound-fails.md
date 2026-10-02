---
section: Migration notes
---
- A B/IP BBMD bound to `0.0.0.0` now fails `start()` unless exactly one BDT row
  names a local address at the bound port, or, with no such row, the host's
  default-route address is one of its own addresses and not loopback. A loaded
  persisted BDT decides on its own; the configured BDT is not tried after it.
  The rules are the same on Windows (#952). Binding the BBMD's interface
  address avoids all of this (#937); see the
  [BBMD section](docs/rust-api.md#bbmd) of the Rust API guide.
