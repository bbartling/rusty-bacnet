# CI and merge evidence

| Platform | Where it is checked |
| --- | --- |
| Linux amd64 | CI, [`.forgejo/workflows/ci.yml`](../.forgejo/workflows/ci.yml) |
| macOS | Locally, [`scripts/ci/local-macos.sh`](../scripts/ci/local-macos.sh) |
| Windows | Not currently tested |

## Pipeline

| Job | PR to `dev` | PR to `main` | Push to `dev` (merge) | Push to `main`, `v*` tag, weekly, manual |
| --- | --- | --- | --- | --- |
| CI image: build and push the job image if its tag is missing | ✓ | ✓ | ✓ | ✓ |
| Lint: rustfmt, 700-LOC cap, no-secret scan, script regressions | ✓ | ✓ | ✓ | ✓ |
| Clippy and rustdoc, warnings denied: every feature, PyO3 crate, each published crate with default features | ✓ | ✓ | ✓ | ✓ |
| Test: Linux, every feature (`LINUX_FEATURES`) | ✓ | ✓ | ✓ | ✓ |
| Python bindings: `maturin develop` (maturin 1.15.0), then `python -m unittest discover -s crates/rusty-bacnet/tests` and the crate's Rust tests (`cargo nextest run -p rusty-bacnet`) | ✓ | ✓ | ✓ | ✓ |
| MSRV 1.93, Linux native (`check-msrv.sh --linux-native`) |  | ✓ |  | ✓ |
| Cargo Audit + Cargo Deny |  | ✓ |  | ✓ |
| **CI OK**: fails if any job above failed | ✓ | ✓ | ✓ | ✓ |

`CI OK` is the single status to require in branch protection (its context is
`CI / CI OK (pull_request)`); jobs skipped by tier count as passing. [`.forgejo/workflows/docs.yml`](../.forgejo/workflows/docs.yml)
validates the website (Astro checks, unit tests, production build and Chromium
tests) on PRs that change `website/**`.

Merge pushes to `dev` run the Lean jobs, for two reasons (#904).

- **Caches.** The runner scopes cache writes from `pull_request` events to that
  PR. A PR's first run falls back only to caches from non-PR events: merges,
  `main`, tags, the schedule or manual runs. Before this, those were rare, so
  most new PRs started cold.
- **Merge result.** A PR run checks out the PR head, not the merge. With the
  repo's default merge commits, the `dev` run is the only test of the combined
  code, and an outdated branch can still merge.

A newer merge cancels the previous merge's run, since it tests a superset.
**After merging, check the `dev` run.** It isn't a required status, so a red
merge run is the only signal of merge skew; fix it forward on `dev` right away.
The weekly scheduled run checks the default branch (`dev`) with the Heavy jobs
too.

Rust caches are keyed per job on the toolchain, `Cargo.lock`, the manifests,
and, for Clippy and Test, `LINUX_FEATURES`. They're saved even when a job
fails.
A new push to a PR cancels its superseded run.

Tests run with [cargo-nextest](https://nexte.st), which gives each test its
own process. Its settings live in [`.config/nextest.toml`](../.config/nextest.toml);
CI uses the `ci` profile, and nextest does not run doctests, so a separate
`cargo test --doc` step covers them. The Linux test commands are below, with
`$LINUX_FEATURES` as set in `ci.yml`: every optional feature that builds on
Linux, including per-crate ones such as `bacnet-endpoint/sc-tls` and
`bacnet-cli/pcap`. A last step runs the `bacnet-cli` tests with default
features, because a few exist only when `sc-tls` or `pcap` is off.

```bash
cargo nextest run --workspace --exclude rusty-bacnet --locked --features "$LINUX_FEATURES" --profile ci
cargo test --doc --workspace --exclude rusty-bacnet --locked --features "$LINUX_FEATURES"
cargo nextest run -p bacnet-cli --locked --profile ci
```

The Python job builds the PyO3 extension in debug mode into a fresh venv with
the CI image's Python (3.12) and runs the unittest suite. The SC tests generate
certificates with the `openssl` CLI. Cargo Deny covers the bindings'
dependencies too; only `bacnet-benchmarks` is excluded.

The same job then runs the crate's Rust tests, its lib unit tests and
integration tests, with `cargo nextest run -p rusty-bacnet --locked --profile ci`.
The workspace doesn't turn on pyo3's `extension-module` feature, so these test
binaries link libpython (#919); maturin turns the feature on for wheel and
`maturin develop` builds from `crates/rusty-bacnet/pyproject.toml`. Linking
needs the interpreter's shared library and its unversioned `.so` symlink, which
the CI image gets from `libpython3-dev`. The step sets `PYO3_PYTHON=/usr/bin/python3`
so it links the apt Python that package matches, whatever else is on `PATH`,
and without depending on the venv from the maturin step. Tests that call into
Python start the interpreter with `Python::initialize()` first, since nothing
enables pyo3's `auto-initialize`.

Use cargo-nextest 0.9.145 or later locally. Older releases on macOS could
mark unrelated passing tests as leaky (#751), and the configuration warns
about them.

### Runner

Jobs run on a self-hosted Linux runner (8 vCPU, 32 GB) on a preemptible VM. It
runs up to three jobs at once, and the host-mode CI image job takes one of those
slots. `Swatinem/rust-cache` keeps Cargo state in the runner's cache. The cache
lives on the VM, so a preemption starts the next run cold, and a preempted job
must be re-run.

### CI image

Every job except CI OK runs in one prebuilt image,
`forgejo.taile9ca5.ts.net/jscott3201/rusty-bacnet-ci:<tag>`, built from
[`.forgejo/ci-image/Dockerfile`](../.forgejo/ci-image/Dockerfile) (#904). It
contains:

- the runner's default `ghcr.io/catthehacker/ubuntu:act-24.04`, pinned by
  digest;
- Rust 1.97.1 with rustfmt and clippy, and the 1.93 MSRV toolchain;
- cargo-nextest, cargo-audit, cargo-deny and maturin at pinned versions, each
  download checked against its SHA-256;
- the apt packages the jobs need.

The jobs no longer spend time on apt, rustup or tool downloads.

The first job, **CI image**, runs on the `linux-host` label. It does three
things:

1. **Tag.** Checks that `CI_IMAGE`'s tag equals the first 12 hex digits of the
   Dockerfile's SHA-256, and that `.forgejo/ci-image` holds nothing but the
   Dockerfile.
2. **Pins.** Checks that the Dockerfile's `RUST_TOOLCHAIN` matches
   `rust-toolchain.toml` and the toolchain pins in `release.yml`, and that its
   `RUST_MSRV` matches `Cargo.toml`'s `rust-version` and the MSRV job's
   `RUSTUP_TOOLCHAIN`.
3. **Image.** Queries Forgejo's container registry for the tag:
   - If the tag exists, it pulls the image into the VM's Docker. The registry
     requires sign-in to pull, and the runner never pulls job images itself
     (`force_pull: false`), so this pull is what gets the image onto a fresh VM
     for the jobs that follow.
   - If the tag is missing, it builds and pushes the image.
   - Any other registry error fails the job.

A PR that changes the Dockerfile therefore builds and tests its own image.

**Changing the image** (a toolchain bump, a tool version, an apt package):

1. Edit the Dockerfile.
   - For a toolchain bump, also move `rust-toolchain.toml` and
     `.github/workflows/release.yml`.
   - For an MSRV bump, also move `Cargo.toml`'s `rust-version`, the MSRV job's
     `RUSTUP_TOOLCHAIN` and `scripts/ci/check-msrv.sh`.
   - For a tool bump, update its `*_SHA256` along with its version.
2. Set `CI_IMAGE`'s tag to
   `$(sha256sum .forgejo/ci-image/Dockerfile | cut -c1-12)`.

Never re-push an existing tag. Change the Dockerfile, even just a comment, to get
a new one.

**Credentials:** the image job logs in with the `CI_IMAGE_TOKEN` repository
secret, a personal access token with only package read and write scope, used for
both the pull and the push.
- Forgejo's automatic job token can log in, but gets 401 on uploads.
- The login uses a Docker config under `RUNNER_TEMP`, which the runner deletes
  even if the job is cancelled.
- If the runner ever gets a second VM, or turns on `force_pull`, give the jobs
  `container.credentials` with a separate read-only package token.

**Storage:** each image version takes space on Forgejo's data disk, and old tags
stay cached on the runner VM until it's rebuilt. Keep the last few versions with
a package cleanup rule, set in the owner's Settings → Packages.

**Caches:** the image sets `CARGO_HOME=/usr/local/cargo`, so switching to it
started every job with a cold Rust cache once. Later image changes keep the same
paths, and the caches still hit while the toolchain stays the same.

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
bash scripts/ci/local-macos.sh          # lint, clippy, rustdoc, macOS tests
bash scripts/ci/local-macos.sh --quick  # lint, clippy and rustdoc only
```

`serial` and `ethernet` are Linux-only features, so macOS uses every other
optional feature. That includes per-crate features such as
`bacnet-endpoint/sc-tls` and `bacnet-cli/{sc-tls,pcap}`, which nothing else in
the workspace turns on, so a transport-only list never built them (#906). CI's
`LINUX_FEATURES` is the same list plus `bacnet-transport/{serial,serial-gpio,ethernet}`
and `bacnet-integration-tests/ethernet`.

The script also runs the PyO3 crate's Rust tests. pyo3 links the libpython of
`PYO3_PYTHON` if it's set, else of the active venv, else of the first `python`
or `python3` on `PATH`. The Homebrew and python.org framework builds both ship
the shared library.

Clippy and rustdoc deny warnings (#902). Every public item must be documented:
`missing_docs` is `deny`, and only the unpublished `bacnet-benchmarks` opts out.
Clippy runs three ways:

- the workspace with every feature;
- the PyO3 crate on its own;
- each published crate alone with default features, plus the `no_std` build of
  `bacnet-types` (`scripts/ci/check-default-features.sh`). This also runs
  rustdoc, which is how docs.rs builds.

The last catches code that compiles only when another crate's feature unifies
in. The individual gates are also runnable anywhere. `FEATURES` is
`LINUX_FEATURES` from `ci.yml`, without the serial and ethernet entries on macOS:

```bash
FEATURES=$(sed -n 's/^  LINUX_FEATURES: //p' .forgejo/workflows/ci.yml)
cargo fmt --all --check
cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked --features "$FEATURES" -- -D warnings
cargo clippy -p rusty-bacnet --all-targets --locked -- -D warnings
bash scripts/ci/check-default-features.sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude rusty-bacnet --no-deps --locked --features "$FEATURES"
cargo nextest run -p bacnet-cli --locked   # the CLI's feature-off tests
cargo nextest run -p rusty-bacnet --locked # the PyO3 crate's Rust tests
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
