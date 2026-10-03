---
section: Migration notes
---
- Review [request admission configuration and migrations](docs/request-admission.md):
  Rust public struct expansions affect exhaustive literals/patterns, small custom
  global limits need an explicit smaller or zero reserve, and independent ordinary
  and recovery peer quotas replace the former inclusive confirmed peer ceiling.
  Python additions remain keyword-only. Service budget documents linked above
  describe new `ServerConfig` fields and limits that large requests may need raised.
