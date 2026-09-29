# CI and merge evidence

| Platform | Where it is checked |
| --- | --- |
| Linux amd64 | CI, [`.forgejo/workflows/ci.yml`](../.forgejo/workflows/ci.yml) |
| macOS | Locally, [`scripts/ci/local-macos.sh`](../scripts/ci/local-macos.sh) |
| Windows | Not currently tested |

## Pipeline

| Job | PR to `dev` | PR to `main` | Push to `main`, `v*` tag, weekly, manual |
| --- | --- | --- | --- |
| Lint: rustfmt, 700-LOC cap, no-secret scan, script regressions | ✓ | ✓ | ✓ |
| Clippy | ✓ | ✓ | ✓ |
| Test: Linux, full features | ✓ | ✓ | ✓ |
| MSRV 1.93, Linux native (`check-msrv.sh --linux-native`) | | ✓ | ✓ |
| Cargo Audit + Cargo Deny | | ✓ | ✓ |
| **CI OK**: fails if any job above failed | ✓ | ✓ | ✓ |

`CI OK` is the single status to require in branch protection (its context is
`CI / CI OK (pull_request)`); jobs skipped by tier count as passing. [`.forgejo/workflows/docs.yml`](../.forgejo/workflows/docs.yml)
validates the website (Astro checks, unit tests, production build and Chromium
tests) on PRs that change `website/**`.

Merge pushes to `dev` do not start a pipeline: the PR already tested that head.
The weekly scheduled run checks the default branch (`dev`).
A new push to a PR cancels its superseded run.

The Linux test command is:

```bash
cargo test --workspace --exclude rusty-bacnet --locked --features bacnet-types/serde,bacnet-transport/ipv6,bacnet-transport/sc-tls,bacnet-transport/serial,bacnet-transport/ethernet
```

### Runner

Jobs run on a self-hosted Linux runner (8 vCPU, 32 GB, up to three concurrent
Docker jobs in `ghcr.io/catthehacker/ubuntu:act-24.04`) on a preemptible VM.
Each job installs its pinned Rust toolchain through `dtolnay/rust-toolchain`;
`Swatinem/rust-cache` keeps Cargo state in the runner's cache. The cache lives
on the VM, so a preemption starts the next run cold, and a preempted job must
be re-run.

The workflow sets `CARGO_INCREMENTAL=0` and drops native debug info from dev and
test builds (`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`) to cut codegen, link time and
cache size. Optimization level, debug assertions, overflow checks and test
selection keep their defaults, and there is no `RUSTFLAGS=-Dwarnings`: per-rule
severity lives in `[workspace.lints]`.

## Local checks

Use Rust 1.97.1 from `rust-toolchain.toml`. Before asking for review on changes
that can affect macOS (transports, sockets, TLS, platform `cfg`, build scripts,
dependencies), run on a Mac:

```bash
bash scripts/ci/local-macos.sh          # lint, clippy, macOS tests (ipv6 + sc-tls)
bash scripts/ci/local-macos.sh --quick  # lint and clippy only
```

`serial` and `ethernet` are Linux-only transport features, so macOS tests the
`ipv6` and `sc-tls` feature set. The individual gates are also runnable anywhere:

```bash
cargo fmt --all --check
cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked
bash scripts/ci/check-file-size.sh
bash scripts/ci/test-check-no-secrets.sh && bash scripts/ci/check-no-secrets.sh
python3 scripts/ci/test-check-msrv.py
```

The no-secret scanner reports stable opaque path IDs and line numbers, never
paths or matching text, because filenames can contain credentials too. Compare
a suspected path locally with `printf '%s' "$path" | git hash-object --stdin`.
Run the file-size gate in its default strict mode, without `CHECK_FILE_SIZE_WARN=1`.

`scripts/ci/check-msrv.sh --linux-native` needs a native Linux GNU host with
Rust 1.93 installed, Python 3, a C toolchain, `pkg-config`, `libpcap-dev`,
`cmake`, `perl`, `file` and `ldd`. It never installs tools or skips features.
CI runs it on PRs to `main`; on a Mac, rely on that job.

## Merge evidence

Before merging a PR:

- `CI OK` is green for the exact head being merged;
- when the change can affect macOS, a `local-macos.sh` pass on that head, or
  on an earlier head with a stated reason the intervening diff cannot affect
  it, is recorded in the PR with the revision, toolchain and macOS version it
  prints;
- existing review and merge-authorization rules are met.

A check that was not run, failed or does not apply is never reported as passed.
Audit and deny read mutable advisory databases, so their result for a `main`
merge comes from that PR's run, not an older one.

## Release and publication

[`.github/workflows/release.yml`](../.github/workflows/release.yml) publishes
crates, wheels, the sdist, CLI binaries and the GitHub release when a `v*` tag
reaches GitHub. It runs on GitHub because it needs GitHub-hosted
macOS/Windows/arm64 runners, the `release` environment secrets and PyPI trusted
publishing. Tag only a commit whose `CI OK` passed on `main`; as a backstop,
publication waits for a full-feature Linux test of the tag. GitHub Pages
publication remains the manual
[`docs-pages.yml`](../.github/workflows/docs-pages.yml) dispatch. Both require
GitHub Actions to be enabled on the GitHub repository.

These checks do not establish Windows support, hardware qualification, installed
Python-extension behavior or release readiness.
