---
section: Fixed
---
- A BACnet/SC dial to a host name with several addresses no longer waits for
  each address in turn (#950). It races them, RFC 8305 style: address
  families alternate, starting with the first result's, and each attempt runs
  alone for 250 ms or until it fails before the next starts; the first
  connection wins. On Windows `localhost` resolves to `::1` first and a
  refused loopback connect takes about 2 seconds, so every hub or direct dial
  to `localhost` with an IPv4-only peer used to take that long. When every
  address fails, the error names each one, and its kind is a refusal if any
  attempt was refused, else a timeout if any timed out.
