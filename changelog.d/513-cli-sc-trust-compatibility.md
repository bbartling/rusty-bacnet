---
section: Changed
---
- **CLI SC trust compatibility change:** `bacnet --sc` client invocations now
  require `--sc-ca <FILE>` with explicit usable site CA PEM certificate(s), in
  addition to the existing operational cert/key and SC identity arguments.
  Native/system roots are no longer loaded; there is no environment-trust or
  insecure fallback. Local file/configuration failures, including mismatched
  cert/key, fail before dial. Help/version, non-SC transports and capture paths
  without a client stay independent of SC files. TLS 1.3-only remains; that CLI change
  left Rust node TLS APIs compatible (subsequent node/hub retirement is described
  above), and #513 remains partial. See the
  [CLI migration and test scope](docs/CLI.md#transport-variants).
