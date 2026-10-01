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
- the apt packages the jobs need;
- for the [release](#release): zig and cargo-zigbuild, the
  `aarch64-unknown-linux-gnu` Rust target, a static libpcap for each release
  target with its licence, uv for the artifact test's extra Pythons, and
  `qemu-aarch64-static` with the aarch64 glibc to run the arm64 CLI.

The jobs no longer spend time on apt, rustup or tool downloads.

The first job, **CI image**, runs on the `linux-host` label. It does three
things:

1. **Tag.** Checks that `CI_IMAGE`'s tag equals the first 12 hex digits of the
   Dockerfile's SHA-256, that `release.yml` uses the same `CI_IMAGE`, and that
   `.forgejo/ci-image` holds nothing but the Dockerfile.
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
2. Set `CI_IMAGE`'s tag, in both `ci.yml` and `release.yml`, to
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
python3 -m unittest discover -s scripts/release
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

## Release

[`.forgejo/workflows/release.yml`](../.forgejo/workflows/release.yml) builds,
tests and publishes a release from Forgejo (#943). It took over while GitHub
Actions is disabled on the mirror (#905). It builds the Linux artifacts only,
and no release is tagged until it also builds macOS and Windows (#944).

[`.github/workflows/release.yml`](../.github/workflows/release.yml) now runs
only when dispatched by hand, so re-enabling Actions can't publish a tag twice.
It is not a way to add macOS or Windows assets to a tag Forgejo already
released: it has no skip logic, and GitHub releases here are immutable once
published. GitHub Pages publication remains the manual
[`docs-pages.yml`](../.github/workflows/docs-pages.yml) dispatch, which needs
GitHub Actions, and Actions is disabled on the mirror.

### Trigger and dry run

- **Tag.** Pushing a `v*` tag to Forgejo runs the whole release.
- **Dry run.** A manual dispatch is a dry run by default (`dry_run` is true). It
  builds and tests every artifact, keeps them as workflow artifacts, makes the
  release API calls read only (see [Release API](#release-api-dry-run)) and
  publishes nothing. The notes come from the workspace version's
  `CHANGELOG.md` section if it has one, otherwise from `[Unreleased]`, which
  may be empty:

  ```bash
  tea api -X POST repos/jscott3201/rusty-bacnet/actions/workflows/release.yml/dispatches \
    --data '{"ref":"dev","inputs":{"dry_run":"true"}}'
  ```

  `dry_run=false` is accepted only on a `v*` tag, where it runs that tag's
  release again.

To release, set the workspace version, add its `CHANGELOG.md` section, merge,
and tag a commit on `main` or `dev`:

```bash
git tag -a v0.12.0 -m "Rusty BACnet 0.12.0"
git push origin v0.12.0
```

The tag push also starts CI on the tagged commit, with the heavy jobs, and the
release waits for it (see [CI gate](#ci-gate)). Before that, and before any
build, the [preflight](#preflight) checks that both release hosts will take
the release.

### Jobs

| Job | What it does |
| --- | --- |
| CI image | Pulls `CI_IMAGE` into the VM's Docker. Only `ci.yml` builds the image, and its image job fails if `release.yml` carries another tag. |
| Validate | Runs the release script tests (`scripts/release/test_*.py`). Checks that every publishable crate has the workspace version and, for a tag, that the tag is `v<version>` and the commit is on `dev` or `main`. For a release, checks that the publish secrets are set and runs the [preflight](#preflight), before anything is built; a dry run runs the preflight's read-only part. Extracts the notes with `changelog_notes.py`, writes `THIRD-PARTY-NOTICES`, then runs the [CI gate](#ci-gate). |
| Crates and sdist | `cargo publish --workspace --dry-run --locked`, which packages every publishable crate and builds each against the others as published. Then the crates.io job's plan (read only), `cargo package` for the `crates` artifact, and `maturin sdist`. |
| Wheels (x86_64, aarch64) | `maturin build --release --locked --zig --compatibility manylinux2014` for CPython 3.11 to 3.14. The image has only Python 3.12; maturin uses its bundled sysconfig for the others. |
| CLI (amd64, arm64) | `cargo zigbuild --release --locked -p bacnet-cli --features sc-tls,pcap` for `<target>.2.17`, against the image's static libpcap. `LIBPCAP_VER` gives the pcap crate libpcap's version, which its build script can't load through the linker-script shim, and must match the image's `/opt/libpcap/VERSION`. |
| Test the artifacts | `check_artifacts.py`: one wheel per Python and architecture with the right tags, version (the workspace version in PEP 440 form) and extension module, `THIRD-PARTY-NOTICES` in each wheel and the sdist, the right ELF architecture, nothing above glibc 2.17 (`objdump -T`), no dynamic libpcap. The Python suite against the installed x86_64 cp312 wheel. `cli_smoke.sh`: the amd64 CLI's `--version` and `--help`, the README quickstart read on loopback, and an offline capture of a one-packet pcap file. The quickstart read again with the server on each other x86_64 wheel, in CPython 3.11, 3.13 and 3.14 from `uv python install`. The arm64 CLI's `--version`, `--help` and offline capture under `qemu-aarch64-static`. |
| Release API (dry run) | Dry runs only. `release_api.py forgejo --dry-run` against Forgejo with the job token, and `release_api.py github --dry-run` if `GH_RELEASE_TOKEN` is set (otherwise a notice says it was skipped). Both read only, for the tag `v<version>`. |
| Publish to crates.io | `publish_crates.sh`: one multi-package `cargo publish --no-verify` of the crates whose version isn't on crates.io yet. Cargo orders them and waits for the index. |
| Publish to PyPI | `maturin upload --skip-existing` of the wheels and the sdist. |
| Forgejo release | `release_api.py forgejo`: [draft, upload, publish](#draft-then-publish). |
| GitHub release copy | `release_api.py github`: checks again that the mirror's tag points at the release commit (the preflight already waited for it), then drafts, uploads, checks and publishes through the GitHub REST API. |

The publish jobs run only for a tag, after every build and test passed, one at
a time in the order above. A failure stops the jobs after it: each publish
job's `if:` starts with `success() &&`, because Forgejo leaves the implicit
`success()` to the runner. Release builds use no Rust cache.

Not tested at run time: the aarch64 wheels (only their tags, module names, ELF
machine and glibc symbols are checked) and the arm64 CLI's network commands.

### CI gate

`scripts/release/ci_gate.py` reads Forgejo's combined status for the commit
(`/repos/{owner}/{repo}/commits/{sha}/status`), which holds the latest status of
each context, so an older success can't hide a newer failure. A release needs
all three of these to be `success`:

- `CI / CI OK (push)`
- `CI / MSRV (Linux native) (push)`
- `CI / Cargo Audit + Deny (push)`

MSRV and audit/deny are heavy jobs, which a dev push skips and a tag push
runs. A dev push's run posts `skipped` for them under the same context names,
and the tag is often on a commit that dev's run has already reported on, so
`skipped` can be the latest state until the tag's run reports. On a tag, the
gate polls every 30 seconds for up to 60 minutes while any of the three is
`pending`, `skipped` or not reported yet. It fails at once on `failure` or
`error` (including `CI OK` failing) or any other state. At the deadline it
fails with what each context showed, and says to re-run the release once the
tag's CI run has passed; a failure's message says to re-run the failed CI jobs
if it was transient. A dry run checks once and only warns. A dispatched CI run
posts no commit statuses, so only push runs count.

The gate reads the combined status page by page. On this Forgejo,
`total_count` is the size of the page, not of the list, so the gate stops at
the first page shorter than the 50 it asks for.

### Preflight

Before anything is built, a release run checks that both hosts will take it,
so that a token or host setting problem stops the run before crates.io and
PyPI, which can't be undone. Validate's "Release preflight" step runs
`release_api.py forgejo --preflight` and then `release_api.py github
--preflight`:

1. **Tag** (GitHub only). `GET /repos/{o}/{r}/git/ref/tags/{tag}` (and
   `git/tags/{sha}` for an annotated tag), polling every 30 seconds for up to
   15 minutes until the push mirror has the tag, which must point at the
   release commit. The repository is public, so this call is anonymous.
2. **Release list.** The release list (`GET /repos/{o}/{r}/releases`, every
   page) with the token, which shows whether the release for the tag is
   absent, a draft the publish job will resume, or published (then only
   checked). A draft made for another commit stops the run here, as the
   publish job would. Drafts named `release-preflight-*` that an earlier run
   couldn't delete are reported, not deleted, since another tag's run may be
   using its own.
3. **Write check.** A disposable draft named `release-preflight-<run id>-<8 hex>`.
   It isn't a `v*` name, so no tag rule applies, and it's unique even when a
   run is re-run. The calls:
   - `POST /repos/{o}/{r}/releases` with `draft: true`, `prerelease: true` and
     `target_commitish: <commit>`. Neither host creates a tag for a draft.
   - The release list again, which must show the new draft: proof that the
     token sees drafts, which resuming a release depends on.
   - Three uploads named like the release's assets: `bacnet-linux-amd64` (one
     byte, extension-less like the CLI binaries, `SHA256SUMS` and
     `THIRD-PARTY-NOTICES`), `rusty_bacnet-0.0.0-py3-none-any.whl` (an empty
     zip) and `rusty_bacnet-0.0.0.tar.gz` (an empty gzip). This proves the
     host's allowed attachment types (Forgejo's `[repository.release]
     ALLOWED_TYPES`) accept every kind.
   - The [final check](#draft-then-publish) on the draft: on GitHub, each
     reported `digest`, and a download of the one-byte file through the API
     asset URL; on Forgejo, each size.
   - `DELETE /repos/{o}/{r}/releases/{id}`.
   - Confirmation: the release list has no release of that name, `GET
     .../releases/{id}` is 404, and no tag of that name exists (GitHub:
     `GET git/ref/tags/<name>` is 404; Forgejo: the whole `GET .../tags` list,
     which comes from git).

The draft is deleted in a `finally` block, whatever failed before: by its id
if the create returned one, and by name from the release list in case the
create's response was lost. If the deletion itself fails, the step fails and
names the draft to delete by hand; if the check had already failed, that
error is reported as well. Forgejo's API never removes a deleted release's
database row: it keeps it as a tag record without a commit, which no API list,
git, the web tags page or the tag count shows, so nothing visible is left.

Any failure stops the release before anything is built, with the reason and
"Nothing has been built or published". A dry run does only the read-only part
(steps 1 and 2, for `v<version>`, and without waiting for the tag), never the
write check; on GitHub it does only the anonymous tag check while
`GH_RELEASE_TOKEN` isn't set, and says so in a notice.

### Draft, then publish

GitHub releases in this repository are immutable once published: assets can't
be added, replaced or deleted, and the tag can't be reused. `release_api.py`
therefore builds each release as a draft and publishes it last. For GitHub:

1. `GET /repos/{o}/{r}/releases` (all pages), matching `tag_name`, because
   `/releases/tags/{tag}` doesn't return drafts. A published release is only
   checked, read only. Otherwise:
2. `POST /repos/{o}/{r}/releases` with `draft: true` and
   `target_commitish: <commit>`, unless a draft exists.
3. `POST uploads.github.com/.../releases/{id}/assets?name=...` for each asset
   the draft lacks.
4. `SHA256SUMS`, computed over the draft's final asset set, uploaded the same
   way (an outdated one is deleted first).
5. The final check, on a fresh `GET` of the draft (below).
6. `PATCH /repos/{o}/{r}/releases/{id}` with `draft: false` and
   `make_latest: "legacy"`, the last call. `legacy` has GitHub pick the latest
   release by date and version, so a backport published after a newer
   release doesn't become the latest.

The Forgejo release follows the same order through Forgejo's API, so
`releases/latest` never shows a half-uploaded release. Forgejo's API has no
`make_latest`: its latest release is the newest published non-prerelease by
creation date, so a backport published after a newer release does show as
Forgejo's latest until the next release.

- **Final check.** The last step before the irreversible publish. The raw
  asset list, before any filtering by state, must hold exactly the expected
  names, once each, with no entry other than `uploaded` (GitHub's `state`).
  Each asset's size must match, and on GitHub its reported `digest`
  (`sha256:<hex>`) must equal the expected sha256: the local file's for an
  upload, the verified digest of an asset kept from an earlier run, and for
  `SHA256SUMS` the sha256 of the text this run computed or found up to date.
  An asset without a digest is downloaded and hashed. Forgejo reports no
  digest and won't serve the assets to the job token, so there the check is
  each asset's size against the local file's (every Forgejo asset is this
  run's upload).
- **Resuming.** A draft left by an earlier run keeps its notes, but only if its
  `target_commitish` is the release commit: a draft made for another commit
  stops the run with a message to delete it. Assets that aren't part of this
  release (the local assets plus `SHA256SUMS`) are deleted first, as are all
  copies of a name that appears more than once (Forgejo allows that; the run
  then uploads one). On GitHub, the other assets are kept, with the checksums
  GitHub reports for them, and `SHA256SUMS` lists what the draft holds.
  Forgejo's web routes, the only way to download an attachment, don't accept
  the job token for a private repository, so on a resumed Forgejo draft this
  run's files replace the existing ones.
- **Published.** The script never uploads to or deletes from a published
  release. It checks that every asset and `SHA256SUMS` are there and, on
  GitHub, that each asset matches `SHA256SUMS`, and fails with an explanation
  otherwise.
- **Retries.** Reads, the final `PATCH` and deletes retry on 5xx and network
  errors, including a truncated response (`http.client.HTTPException`, such
  as `IncompleteRead`). Deletes treat 404 as done, so a retried delete
  succeeds. A `POST` doesn't retry: after an uncertain upload failure, or
  GitHub's 422 `already_exists`, the script lists the draft's assets again
  and accepts the asset if it's complete and matches (digest on GitHub, size
  on Forgejo), or deletes it and sends the file again. A failed create looks
  for the draft before trying again.
- **Downloads.** GitHub serves a draft's assets only through the API asset URL
  with `Accept: application/octet-stream`. The token goes in an unredirected
  header, so the redirect to storage never carries it.

#### Release API (dry run)

The dry run calls the same code with `--dry-run`, which makes no write: it
finds the release, checks a published one, prints the deletions and uploads a
real run would make (or warns that a draft for another commit would stop it)
and, on GitHub, downloads the smallest existing asset. While the workspace
version is already released, the check reports what the published release
lacks as a warning.

### Artifacts

- `release-assets`: what the publish jobs upload, which the releases also get
  with a `SHA256SUMS` file:
  - `bacnet-linux-amd64` and `bacnet-linux-arm64`, with BACnet/SC and packet
    capture;
  - `rusty_bacnet-<version>.tar.gz`, the sdist;
  - eight wheels, `rusty_bacnet-<version>-cp3XY-cp3XY-manylinux_2_17_<arch>.manylinux2014_<arch>.whl`
    for CPython 3.11 to 3.14 on x86_64 and aarch64;
  - `THIRD-PARTY-NOTICES`.
- `release-notes`: `notes.md` for Forgejo, and `notes-github.md` for GitHub.
  GitHub refuses bodies over 125,000 characters, so a longer section is cut at
  120,000 with a link to the full `CHANGELOG.md`, closing any code block the
  cut leaves open. The 0.11.0 section is about 171,000.
- `notices`: `THIRD-PARTY-NOTICES`, which the sdist and wheel jobs build in.
- `crates`, `sdist`, `wheels-<arch>` and `cli-<arch>`: each build job's output.

The Linux binaries and wheels need glibc 2.17 or newer, which covers
RHEL/CentOS 7, Debian 8, Ubuntu 14.04 and later. zig links them against that
glibc, so no manylinux container is involved. The CLI links libpcap 1.10.7
statically, built for each target in the CI image: Debian and Ubuntu name the
shared library `libpcap.so.0.8` and RHEL `libpcap.so.1`, so one dynamically
linked binary couldn't run on both. The pcap crate links `-lpcap` as a shared
library and zig won't fall back to an archive, so the image puts a one-line
linker script named `libpcap.so` next to `libpcap.a`.

### Third-party notices

`scripts/release/third_party_notices.py` writes `THIRD-PARTY-NOTICES`: Rusty
BACnet's own licence, then every third-party component in the release
binaries with the licence files it ships, identical texts printed once.

- The crates come from `cargo tree --locked --offline -e normal,no-proc-macro`
  for the CLI (`-p bacnet-cli --features sc-tls,pcap`) and the Python extension
  (`-p rusty-bacnet`) on both Linux targets, so build scripts, proc-macros and
  dev-dependencies, which neither binary contains, are left out. The licence
  files are the ones at each crate's root, plus three for the C library that
  `aws-lc-sys` bundles: `aws-lc/LICENSE`, fiat-crypto's
  `aws-lc/third_party/fiat/LICENSE` (MIT), and the licence comment of
  jitterentropy's `jitterentropy.h`, which is built on Linux and whose
  BSD-3-Clause terms AWS-LC elects (the crate doesn't ship jitterentropy's
  `LICENSE`).
- Every component's row gives where its source is: a crate's crates.io page
  for that version (`https://crates.io/crates/{name}/{version}`), or its
  repository if it isn't from crates.io; libpcap's release tarball on
  tcpdump.org. MPL-2.0 needs this for `serialport`, which is in the wheels.
- Generation fails if a crate ships no licence file while its licence
  expression has any identifier other than the public-domain-like `0BSD`,
  `CC0-1.0`, `MIT-0`, `Unlicense` and `WTFPL` (so MIT, BSD-*, ISC,
  Apache-2.0, MPL-2.0 and unknown ones all count), unless
  `ALLOW_NO_LICENSE_FILE` in the script names it with the reason. The list is
  empty: every such crate ships a licence file.
- libpcap's licence and version come from `/opt/libpcap` in the CI image.
- The file depends only on `Cargo.lock`, the crate sources and libpcap, so a
  rebuild writes the same file.

It's attached to each release, and `pyproject.toml`'s `license-files` puts it
in each wheel's `.dist-info/licenses/` and in the sdist; the artifact test
checks both. Local builds have no such file, and maturin skips it.

cargo-audit and cargo-deny don't cover libpcap, so its advisories need
tracking by hand: watch the [tcpdump/libpcap
releases](https://www.tcpdump.org/) and their security fixes, and bump
`LIBPCAP_VERSION` in the Dockerfile and `LIBPCAP_VER` in `release.yml`
together.

### Re-running a partial release

Every publish job skips what's already there: crate versions on crates.io,
files on PyPI, and a release that is already published. A draft is resumed as
[above](#draft-then-publish).

Forgejo deletes all of a run's artifacts whenever any of its jobs is re-run, so
re-running only a failed publish job would find nothing to upload. To finish a
release, for example after a network failure, use **"Re-run all jobs"** on the
tag's run, or dispatch the workflow on the tag with `dry_run=false`. Both
rebuild and test everything before the publish jobs pick up where they stopped.

Rebuilding a commit has given identical files: two dry runs of `685e23ed`
(runs 79 and 80, 2026-10-01) produced the same SHA-256 for all 12
`release-assets` files. The jobs use the same image, paths and toolchain, with
`SOURCE_DATE_EPOCH` set to the commit time for the sdist and wheels, but
nothing enforces it. If a rebuild ever differed, PyPI would keep the files it
already has, a published release wouldn't change, and `SHA256SUMS` would
still list exactly what each release holds.

### Secrets

Repository secrets, each passed only to the step that needs it:

- `CI_IMAGE_TOKEN`: pulls the CI image, as in `ci.yml`.
- `CARGO_REGISTRY_TOKEN`: a crates.io token that can publish new crates and
  update existing ones. 0.12.0 is the first release of `bacnet-endpoint` and
  `bacnet-cli`.
- `PYPI_PUBLISH`: a PyPI API token for `rusty-bacnet`, used as `__token__`.
- `GH_RELEASE_TOKEN`: a fine-grained GitHub token for `jscott3201/rusty-bacnet`
  with Contents read and write. Validate's preflight uses it too, to list
  releases and to create and delete its disposable draft.
- The job's automatic token creates the Forgejo release, makes and deletes the
  preflight's draft, and reads commit statuses. Validate and the Forgejo
  release job declare `contents: write` for when Forgejo honours
  `permissions`.

For a release, Validate fails before any build if `CARGO_REGISTRY_TOKEN`,
`PYPI_PUBLISH` or `GH_RELEASE_TOKEN` is empty; a dry run only warns. The step
sees only whether each is set, never its value.

### macOS and Windows

The runner is one Linux x86_64 VM, so the workflow builds only Linux binaries
and wheels. Cross-compiled macOS and Windows builds are #944, and releases
wait for them.

These checks do not establish Windows support, hardware qualification or
release readiness.
