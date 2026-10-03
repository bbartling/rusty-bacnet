---
section: Changed
---
- **Breaking (CLI):** `bacnet-sc-hub` requires `--ca`, `--cert` and `--key`,
  and `bacnet-device --transport=sc` its SC credentials and identity, for
  mutual TLS 1.3; see the [Docker recipe](examples/docker/README.md) (#513).
