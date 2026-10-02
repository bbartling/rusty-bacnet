#!/usr/bin/env bash
# Clippy and rustdoc for each publishable crate on its own, with default
# features and only its lib/bin targets, denying warnings. Also covers the
# no_std build of bacnet-types.
#
#   check-default-features.sh               for the host
#   check-default-features.sh <triple>...   for those targets; cargo checks
#                                           them side by side, in one run
#
# The workspace runs cannot catch code or docs that only work with a feature
# on: cargo unifies features across the selected members, and --all-targets
# pulls in dev-dependencies that turn optional features (such as sc-tls) back
# on. A published crate built alone with defaults hit exactly that (#908), and
# docs.rs builds with default features too. Crates come from `cargo metadata`,
# so a new publishable crate is covered without editing this list.
#
# Linux CI runs it for Linux, Windows and macOS (#981), whose platform cfgs
# compile different code. Neither clippy nor rustdoc links, and no C code
# builds with default features, so another target needs only its standard
# library (`rustup target add`), not cargo-xwin or zig. A default-feature
# dependency with a C build script would change that.
set -euo pipefail

targets=()
for triple in "$@"; do
  case $triple in -*|'') echo "usage: $0 [<target triple>...]" >&2; exit 2 ;; esac
  targets+=(--target "$triple")
done
label=${*:+; $*}
# cargo <subcommand> with the --target options. macOS's bash 3.2 treats an
# empty array as unset under `set -u`, hence the ${...+...}.
cargo_for() { local sub=$1; shift; cargo "$sub" ${targets[@]+"${targets[@]}"} "$@"; }

crates=$(cargo metadata --no-deps --format-version 1 --locked | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p.get("publish") != []:
        print(p["name"])
')
[ -n "$crates" ] || { echo "error: cargo metadata listed no publishable crates" >&2; exit 1; }

export RUSTDOCFLAGS="-D warnings"
for crate in $crates; do
  echo "==> $crate (default features$label)"
  cargo_for clippy -p "$crate" --locked -- -D warnings
  cargo_for doc -p "$crate" --no-deps --locked
done

echo "==> bacnet-types (no_std$label)"
cargo_for clippy -p bacnet-types --no-default-features --locked -- -D warnings
cargo_for doc -p bacnet-types --no-default-features --no-deps --locked
