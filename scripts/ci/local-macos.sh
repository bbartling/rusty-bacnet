#!/usr/bin/env bash
# Local macOS checks, optional. The native-tests workflow on GitHub runs the
# macOS tests, clippy and rustdoc for every pushed branch, and that is the merge
# evidence (see docs/ci.md). Run this on a Mac for a quicker answer before
# pushing changes that can affect macOS (transports, sockets, TLS, platform cfg,
# build scripts, dependencies). Usage, from anywhere in the repo:
#
#   bash scripts/ci/local-macos.sh          # lint + clippy + macOS tests
#   bash scripts/ci/local-macos.sh --quick  # skip the test suite
#
# serial and ethernet are Linux-only features, so macOS uses every other
# optional feature, including those crates gate on their own features (#906).
# Clippy and rustdoc deny warnings, as CI does. Tests need cargo-nextest
# 0.9.145 or later (`cargo install cargo-nextest --locked`). The PyO3 crate's
# Rust tests link libpython from PYO3_PYTHON, the active venv, or `python` /
# `python3` on PATH, in that order (#919). .github/workflows/native-tests.yml
# reads the features= line below, so keep it a single line.
set -euo pipefail

cd "$(dirname "$0")/../.."
[ "$(uname -s)" = Darwin ] || { echo "error: run this on macOS" >&2; exit 1; }

quick=false
case "${1:-}" in
  "") ;;
  --quick) quick=true ;;
  *) echo "usage: local-macos.sh [--quick]" >&2; exit 2 ;;
esac

step() { printf '\n==> %s\n' "$*"; }

step "rev $(git rev-parse --short HEAD)$(git diff --quiet HEAD || echo ' (+ uncommitted changes)'), $(rustc --version), macOS $(sw_vers -productVersion) $(uname -m)"
step "rustfmt";          cargo fmt --all --check
step "file-size cap";    bash scripts/ci/check-file-size.sh
step "no-secret scan";   bash scripts/ci/test-check-no-secrets.sh && bash scripts/ci/check-no-secrets.sh
step "MSRV script regressions"; python3 scripts/ci/test-check-msrv.py
features=bacnet-types/serde,bacnet-transport/ipv6,bacnet-transport/sc-tls,bacnet-client/ipv6,bacnet-client/sc-tls,bacnet-server/sc-tls,bacnet-endpoint/sc-tls,bacnet-integration-tests/ipv6,bacnet-cli/sc-tls,bacnet-cli/pcap
step "clippy (every macOS feature)"
cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked --features "$features" -- -D warnings
step "clippy (PyO3 bindings)"; cargo clippy -p rusty-bacnet --all-targets --locked -- -D warnings
step "clippy and rustdoc (each published crate, default features; no_std bacnet-types)"
bash scripts/ci/check-default-features.sh
step "rustdoc (every macOS feature)"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude rusty-bacnet --no-deps --locked --features "$features"
if ! "$quick"; then
  cargo nextest --version >/dev/null 2>&1 \
    || { echo "error: cargo-nextest not found; cargo install cargo-nextest --locked" >&2; exit 1; }
  step "tests (every macOS feature)"
  cargo nextest run --workspace --exclude rusty-bacnet --locked --features "$features"
  step "doctests"
  cargo test --doc --workspace --exclude rusty-bacnet --locked --features "$features"
  step "bacnet-cli tests (default features)"
  cargo nextest run -p bacnet-cli --locked
  step "PyO3 crate Rust tests"
  cargo nextest run -p rusty-bacnet --locked
fi
step "OK: macOS checks passed"
