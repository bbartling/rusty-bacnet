---
section: Fixed
commit: 7abb5e451793bca30c923e2244e6bba93efea336
---
- A BACnet/SC dial to a host name with several addresses races them, Happy
  Eyeballs style, instead of trying each in turn (#950).
