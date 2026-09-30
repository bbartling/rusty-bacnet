#!/usr/bin/env bash
# Local macOS checks. Forgejo CI covers Linux only, so run this on a Mac before
# asking for review on changes that can affect macOS (transports, sockets, TLS,
# platform cfg, build scripts, dependencies). Usage, from anywhere in the repo:
#
#   bash scripts/ci/local-macos.sh          # lint + clippy + macOS tests
#   bash scripts/ci/local-macos.sh --quick  # skip the test suite
#
# serial and ethernet are Linux-only transport features, so macOS runs the
# ipv6 + sc-tls feature set. Tests need cargo-nextest 0.9.145 or later
# (`cargo install cargo-nextest --locked`). Record the result in the PR (see
# docs/ci.md).
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
step "clippy";           cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked
if ! "$quick"; then
  features=bacnet-types/serde,bacnet-transport/ipv6,bacnet-transport/sc-tls
  cargo nextest --version >/dev/null 2>&1 \
    || { echo "error: cargo-nextest not found; cargo install cargo-nextest --locked" >&2; exit 1; }
  step "tests (ipv6, sc-tls)"
  cargo nextest run --workspace --exclude rusty-bacnet --locked --features "$features"
  step "doctests"
  cargo test --doc --workspace --exclude rusty-bacnet --locked --features "$features"
fi
step "OK: macOS checks passed"
