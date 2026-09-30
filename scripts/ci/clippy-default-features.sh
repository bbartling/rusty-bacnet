#!/usr/bin/env bash
# Clippy each publishable crate on its own, with default features and only its
# lib/bin targets, denying warnings.
#
# The workspace clippy run cannot catch code that only compiles with a feature
# on: cargo unifies features across the selected members, and --all-targets
# pulls in dev-dependencies that turn optional features (such as sc-tls) back
# on. A published crate built alone with defaults hit exactly that (#908), so
# each one gets its own run here. Crates come from `cargo metadata`, so a new
# publishable crate is covered without editing this list.
set -euo pipefail

crates=$(cargo metadata --no-deps --format-version 1 --locked | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p.get("publish") != []:
        print(p["name"])
')

for crate in $crates; do
  echo "==> $crate (default features)"
  cargo clippy -p "$crate" --locked -- -D warnings
done
