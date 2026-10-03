---
section: Fixed
---
- The Python B/IP endpoint tests bind port 0 and read the bound port back from
  `local_address()` instead of probing a free port on 127.0.0.1 first. B/IP
  binds the wildcard address, so a port free on loopback could be in use there,
  and any process could take it between the probe and the bind (#993). The
  audit-policy endpoint test does the same, and the `server_only` endpoint
  example, which needs its port before it starts, now probes the wildcard
  address.
