---
section: Changed
---
- **Breaking (CLI):** `bacnet --sc` requires `--sc-ca` with explicit site CA
  certificates and no longer loads the system roots; see the
  [CLI migration](docs/CLI.md#transport-variants) (#513).
