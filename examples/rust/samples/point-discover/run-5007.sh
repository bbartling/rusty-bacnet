#!/usr/bin/env bash
# Discover device 5007 via Who-Is, enumerate points, exit.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A workspace member: cargo run builds it into the workspace's target/ first
# when needed.
RUN=(cargo run --release --manifest-path "$ROOT/Cargo.toml" --)

ARGS=(
  --device "${BACNET_DEVICE_INSTANCE:-5007}"
  --interface "${BACNET_BIND_ADDRESS:-192.168.204.55}"
  --broadcast "${BACNET_BROADCAST:-192.168.204.255}"
)

if [[ -n "${BACNET_DEVICE_ADDRESS:-}" ]]; then
  ARGS+=(--address "$BACNET_DEVICE_ADDRESS")
fi

exec "${RUN[@]}" "${ARGS[@]}" "$@"
