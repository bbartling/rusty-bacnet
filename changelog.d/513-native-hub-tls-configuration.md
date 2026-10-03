---
section: Changed
---
- `ScHubTlsConfig::from_der` builds hub TLS from loaded CA, chain and key DER
  with mandatory client verification and TLS 1.3 only, and Python hub startup
  uses it (#513).
