---
section: Fixed
commit: 7abb5e451793bca30c923e2244e6bba93efea336
---
- A peer that the SC hub or a direct-connection listener refuses during the
  TLS handshake can now read the alert that says why, instead of seeing a
  connection reset (#950).
