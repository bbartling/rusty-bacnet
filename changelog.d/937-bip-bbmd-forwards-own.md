---
section: Fixed
commit: 873fd0cc97b25f0d137ffa30fb27698e39f3be8a
---
- **Wire:** a B/IP BBMD forwards its own broadcasts to its BDT peers and
  foreign devices, takes its own address from its BDT when bound to `0.0.0.0`,
  and no longer rebroadcasts a broadcast Forwarded-NPDU locally (#937, #952).
