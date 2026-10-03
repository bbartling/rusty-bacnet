---
section: Added
---
- `rusty_bacnet.list_serial_ports()` returns the names of the serial ports the
  operating system reports, to pass as `serial_port=` for MS/TP, and
  `bacnet_transport::mstp_serial::available_ports()` is its Rust counterpart.
  macOS lists them through IOKit, Windows through SetupAPI and the registry, and
  Linux from sysfs. The release smoke test calls it on every platform, which on
  macOS proves the wheels' IOKit and CoreFoundation links at run time (#951).
