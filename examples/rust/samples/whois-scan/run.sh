#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A workspace member: cargo run builds it into the workspace's target/ first
# when needed.
RUN=(cargo run --release --manifest-path "$ROOT/Cargo.toml" --)

exec "${RUN[@]}" \
  --interface "${BACNET_BIND_ADDRESS:-192.168.204.55}" \
  --broadcast "${BACNET_BROADCAST:-192.168.204.255}" \
  --timeout "${BACNET_SCAN_TIMEOUT:-3}" \
  "$@"
