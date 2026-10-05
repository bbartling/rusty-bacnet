#!/usr/bin/env bash
# Foreground mini-device with discovery-friendly settings (run from any directory).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# A workspace member: cargo run builds it into the workspace's target/ first
# when needed.
RUN=(cargo run --release --manifest-path "$ROOT/mini-device-revisited/Cargo.toml" --)

export RUST_LOG="${RUST_LOG:-debug,mini_device_revisited=debug,bacnet_server=debug,bacnet_transport=debug,bacnet_network=debug}"

exec "${RUN[@]}" \
  --name "${BACNET_DEVICE_NAME:-BensServerTest}" \
  --instance "${BACNET_DEVICE_INSTANCE:-3456}" \
  --address "${BACNET_BIND_ADDRESS:-192.168.204.55}" \
  --broadcast "${BACNET_BROADCAST:-192.168.204.255}" \
  --debug \
  "$@"
