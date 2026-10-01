#!/usr/bin/env bash
# Publish every publishable workspace crate whose version isn't on crates.io
# yet, in one multi-package `cargo publish`, which orders the crates and waits
# for each to reach the index before its dependents (#943).
#
#   scripts/release/publish_crates.sh            needs CARGO_REGISTRY_TOKEN
#   scripts/release/publish_crates.sh --dry-run  only list what it would publish
#
# Safe to re-run: versions already on crates.io are skipped. Crates with
# `publish = false` are never considered. --no-verify, because the release
# workflow's "Crates and sdist" job already ran `cargo publish --workspace
# --dry-run --locked` on the same commit.
set -euo pipefail

dry_run=false
[ "${1:-}" = --dry-run ] && dry_run=true
ua="rusty-bacnet-release (+https://github.com/jscott3201/rusty-bacnet)"

crates=$(cargo metadata --no-deps --format-version 1 --locked \
  | jq -r '.packages[] | select(.publish != []) | "\(.name) \(.version)"')
[ -n "$crates" ] || { echo "::error::cargo metadata listed no publishable crates"; exit 1; }

todo=()
while read -r name version; do
  code=$(curl -sS --retry 3 -o /dev/null -w '%{http_code}' -A "$ua" \
    "https://crates.io/api/v1/crates/$name/$version")
  case "$code" in
    200) echo "skip $name $version: already on crates.io" ;;
    404) echo "publish $name $version"; todo+=(-p "$name") ;;
    *) echo "::error::crates.io answered HTTP $code for $name $version"; exit 1 ;;
  esac
done <<<"$crates"

if [ ${#todo[@]} -eq 0 ]; then
  echo "Every publishable crate is already on crates.io."
  exit 0
fi
if $dry_run; then
  echo "dry run: would run cargo publish --locked --no-verify ${todo[*]}"
  exit 0
fi
: "${CARGO_REGISTRY_TOKEN:?CARGO_REGISTRY_TOKEN is not set}"
cargo publish --locked --no-verify "${todo[@]}"
