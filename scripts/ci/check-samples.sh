#!/usr/bin/env bash
# cargo check --locked for every standalone sample in examples/rust/samples
# (#1406), lib/bin and test targets. The samples sit outside the workspace,
# each with its own manifest and Cargo.lock, so no workspace build compiles
# them, and a sample could stop building or its lock go stale unnoticed.
# Samples are found by their Cargo.toml, so a new one is covered without
# editing this script. Usage, from anywhere in the repo:
#
#   bash scripts/ci/check-samples.sh
#
# Every sample builds into one target directory, so the dependencies they
# share compile once: $CARGO_TARGET_DIR if set, otherwise target/samples at the
# repo root, a target directory of its own beside the workspace's.
#
# A sample whose Cargo.lock no longer matches its manifest or the bacnet-*
# crates it depends on by path (one gained a dependency, or the workspace
# version moved) fails here. Refresh that lock with
#
#   cargo update --workspace --manifest-path examples/rust/samples/<name>/Cargo.toml
#
# which updates only the sample's path crates, not any locked registry
# version, then commit it.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/samples}"

found=0
failed=
for manifest in examples/rust/samples/*/Cargo.toml; do
  [ -f "$manifest" ] || continue
  found=$((found + 1))
  name=$(basename "$(dirname "$manifest")")
  printf '\n==> %s\n' "$name"
  # Resolving with --locked fails before any build when the lock is stale, and
  # gives that case its own hint.
  if ! err=$(cargo metadata --locked --format-version 1 --manifest-path "$manifest" 2>&1 >/dev/null); then
    printf '%s\n' "$err" >&2
    case $err in
      *"cannot update the lock file"*)
        echo "error: $name's Cargo.lock is stale; refresh it with:" >&2
        echo "  cargo update --workspace --manifest-path $manifest" >&2 ;;
    esac
    failed="$failed $name"
    continue
  fi
  cargo check --locked --all-targets --manifest-path "$manifest" || failed="$failed $name"
done

[ "$found" -gt 0 ] || { echo "error: no samples found in examples/rust/samples" >&2; exit 1; }
if [ -n "$failed" ]; then
  echo "error: samples that failed:$failed" >&2
  exit 1
fi
echo "OK: $found samples check with --locked"
