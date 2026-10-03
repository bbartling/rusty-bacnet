---
section: Fixed
---
- On Windows, a B/IP or B/IPv6 transport on an ephemeral port now owns the
  port (#950). It binds the wildcard address without SO_REUSEADDR, and
  Windows still let another socket bind a more specific address on the same
  port (127.0.0.1 beside 0.0.0.0) and take the unicast sent there. Such
  sockets now set SO_EXCLUSIVEADDRUSE. Linux already refuses that bind. macOS
  refuses it too unless the other socket sets SO_REUSEADDR, and has no option
  to close that case. Explicitly configured ports keep SO_REUSEADDR.
