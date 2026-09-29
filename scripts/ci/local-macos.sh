#!/usr/bin/env bash
# Local macOS checks. Forgejo CI covers Linux only, so run this on a Mac before
# asking for review on changes that can affect macOS (transports, sockets, TLS,
# platform cfg, build scripts, dependencies). Usage, from anywhere in the repo:
#
#   bash scripts/ci/local-macos.sh          # lint + clippy + macOS tests
#   bash scripts/ci/local-macos.sh --quick  # skip the test suite
#
# serial and ethernet are Linux-only transport features, so macOS runs the
# ipv6 + sc-tls feature set. Record the result in the PR (see docs/ci.md).
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
step "clippy";           cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked
if ! "$quick"; then
  step "tests (ipv6, sc-tls)"
  cargo test --workspace --exclude rusty-bacnet --locked \
    --features bacnet-types/serde,bacnet-transport/ipv6,bacnet-transport/sc-tls
fi
step "OK: macOS checks passed"
