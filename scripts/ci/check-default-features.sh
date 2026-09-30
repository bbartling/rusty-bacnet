#!/usr/bin/env bash
# Clippy and rustdoc for each publishable crate on its own, with default
# features and only its lib/bin targets, denying warnings. Also covers the
# no_std build of bacnet-types.
#
# The workspace runs cannot catch code or docs that only work with a feature
# on: cargo unifies features across the selected members, and --all-targets
# pulls in dev-dependencies that turn optional features (such as sc-tls) back
# on. A published crate built alone with defaults hit exactly that (#908), and
# docs.rs builds with default features too. Crates come from `cargo metadata`,
# so a new publishable crate is covered without editing this list.
set -euo pipefail

crates=$(cargo metadata --no-deps --format-version 1 --locked | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p.get("publish") != []:
        print(p["name"])
')
[ -n "$crates" ] || { echo "error: cargo metadata listed no publishable crates" >&2; exit 1; }

export RUSTDOCFLAGS="-D warnings"
for crate in $crates; do
  echo "==> $crate (default features)"
  cargo clippy -p "$crate" --locked -- -D warnings
  cargo doc -p "$crate" --no-deps --locked
done

echo "==> bacnet-types (no_std)"
cargo clippy -p bacnet-types --no-default-features --locked -- -D warnings
cargo doc -p bacnet-types --no-default-features --no-deps --locked
