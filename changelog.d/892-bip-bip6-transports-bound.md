---
section: Fixed
---
- B/IP and B/IPv6 transports bound to port 0 no longer set `SO_REUSEADDR`,
  which on Linux could let two sockets share an ephemeral port and lose
  replies (#892).
