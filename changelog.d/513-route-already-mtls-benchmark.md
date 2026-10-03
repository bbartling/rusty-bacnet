---
section: Changed
---
- Route the already-mTLS benchmark hub launcher and CLI/server SC test fixtures
  through `ScHubTlsConfig`, preserving identity, timeout and lifecycle behavior.
  Add focused benchmark PEM-loader validation tests; independent raw TLS peer
  helpers and production CLI/node APIs remain unchanged. This was further
  opt-in adoption, not raw-API retirement, performance qualification or #513 closure.
