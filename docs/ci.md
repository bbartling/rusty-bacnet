# CI and merge evidence

The repository, its pull requests and its CI live on
[GitHub](https://github.com/jscott3201/rusty-bacnet), and every CI job runs on
GitHub-hosted runners, the [release](#release) included.

| Host | Runs |
| --- | --- |
| GitHub (hosted runners) | Linux CI, [`.github/workflows/ci.yml`](../.github/workflows/ci.yml); [native macOS and Windows tests](#native-tests-macos-and-windows), [`native-tests.yml`](../.github/workflows/native-tests.yml); website validation and the GitHub Pages deploy, [`docs-pages.yml`](../.github/workflows/docs-pages.yml); [releases](#release), built and tested on each platform and published to crates.io, PyPI and GitHub Releases, [`release.yml`](../.github/workflows/release.yml) |

| Platform | Where it is checked |
| --- | --- |
| Linux amd64 | CI: lint, clippy, rustdoc, tests, Python bindings, MSRV, audit and deny |
| macOS arm64 | Native tests: tests, doctests, clippy, rustdoc, Python bindings. CI: clippy and rustdoc for each published crate with default features, cross-checked |
| Windows x86_64 (MSVC) | Native tests: tests, doctests, clippy, rustdoc, Python bindings. CI: clippy and rustdoc for each published crate with default features, cross-checked |

A PR merges only when both required checks are green on its head SHA: `CI OK`
from `ci.yml` and `Native OK` from `native-tests.yml`, each of which passes
only when every job under it did (see [Merge evidence](#merge-evidence)).

## Pipeline

| Job | PR to `dev` | PR to `main` | Push to `dev` (merge) | Push to `main`, `v*` tag, weekly, manual |
| --- | --- | --- | --- | --- |
| Lint: rustfmt, 700-LOC cap, no-secret scan, script regressions, changelog fragments, the [tool pins](#tool-pins) | ✓ | ✓ | ✓ | ✓ |
| Clippy and rustdoc, warnings denied: every feature, PyO3 crate, `bacnet-cli` without default features, each published crate with default features for Linux, Windows and macOS; the every-feature and PyO3 rustdoc runs include private items. The workspace runs include the [samples](#samples) | ✓ | ✓ | ✓ | ✓ |
| Test: Linux, every feature (`LINUX_FEATURES`) | ✓ | ✓ | ✓ | ✓ |
| Python bindings: `maturin develop` (maturin at its [pinned](#tool-pins) version), then `python -m unittest discover -s crates/rusty-bacnet/tests` and the crate's Rust tests (`cargo nextest run -p rusty-bacnet`) | ✓ | ✓ | ✓ | ✓ |
| MSRV (`RUST_MSRV` in [`.github/ci-pins.env`](../.github/ci-pins.env)), Linux native (`check-msrv.sh --linux-native`) |  | ✓ |  | ✓ |
| Cargo Audit + Cargo Deny |  | ✓ |  | ✓ |
| **CI OK**: fails if any job above failed | ✓ | ✓ | ✓ | ✓ |
| Prune caches, after a green run on `dev` ([Caches](#caches)) |  |  | ✓ | weekly, and manual on `dev` |

`CI OK` is the required check. MSRV and Cargo Audit + Deny count as passing
when their tier skips them; a skipped Lean job fails it.
[`docs-pages.yml`](../.github/workflows/docs-pages.yml) validates the website
(Astro checks, unit tests, production build and Chromium tests) on PRs that
change `website/**`.

Merge pushes to `dev` run the Lean jobs, for two reasons (#904).

- **Caches.** Only runs on `dev` save the Rust caches. A cache saved by a
  `pull_request` run would be scoped to that PR, and a PR run restores from
  its base branch and the default branch (`dev`), so `dev`'s caches seed
  every PR.
- **Merge result.** A PR run tests the PR head merged into its base as the
  base stood when the run started (GitHub's `refs/pull/<n>/merge`). With the
  repo's merge commits, the `dev` run is the only test of what actually
  landed, after any merges since.

A newer merge cancels the previous merge's run, since it tests a superset.
**After merging, check the `dev` run.** It isn't a required status, so a red
merge run is the only signal of merge skew; fix it forward on `dev` right away.
The weekly scheduled run checks the default branch (`dev`) with the Heavy jobs
too.

Rust caches are keyed per job on the toolchain, `Cargo.lock`, the manifests,
and, for Clippy and Test, `LINUX_FEATURES` (Clippy also on
`DEFAULT_FEATURES_TARGETS`). Only a job that succeeded on `dev` saves its
cache, so a failed or cancelled run can't leave a partial cache that later runs
restore by exact key. The MSRV job's cache comes from the weekly run, the Heavy run on
`dev`. A new push to a PR cancels its superseded run.

The workflow sets `CARGO_INCREMENTAL=0` and drops native debug info from dev and
test builds (`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`) to cut codegen, link time and
cache size. Optimization level, debug assertions, overflow checks and test
selection keep their defaults, and there is no `RUSTFLAGS=-Dwarnings`: per-rule
severity lives in `[workspace.lints]`.

Tests run with [cargo-nextest](https://nexte.st), which gives each test its
own process. Its settings live in [`.config/nextest.toml`](../.config/nextest.toml);
CI uses the `ci` profile, and nextest does not run doctests, so a separate
`cargo test --doc` step covers them. The tests that take 3.5 s or more have a
`priority` there, so they start first instead of running alone at the end; the
file says how to refresh that list. The Linux test commands are below, with
`$LINUX_FEATURES` as set in `ci.yml`: every optional feature that builds on
Linux, including per-crate ones such as `bacnet-endpoint/sc-tls` and
`bacnet-cli/pcap`. The last steps run the `bacnet-cli` tests with default
features, because a few exist only when `sc-tls` or `pcap` is off, and with no
default features, because a few exist only when the default `tui` feature is
off.

```bash
cargo nextest run --workspace --exclude rusty-bacnet --locked --features "$LINUX_FEATURES" --profile ci
cargo test --doc --workspace --exclude rusty-bacnet --locked --features "$LINUX_FEATURES"
cargo nextest run -p bacnet-cli --locked --profile ci
cargo nextest run -p bacnet-cli --no-default-features --locked --profile ci
```

The Python job builds the PyO3 extension in debug mode into a fresh venv with
Ubuntu 24.04's own Python (3.12) and runs the unittest suite. The SC tests
generate certificates with the `openssl` CLI. Cargo Deny covers the bindings'
dependencies too; only `bacnet-benchmarks` is excluded.

The same job then runs the crate's Rust tests, its lib unit tests and
integration tests, with `cargo nextest run -p rusty-bacnet --locked --profile ci`.
The workspace doesn't turn on pyo3's `extension-module` feature, so these test
binaries link libpython (#919); maturin turns the feature on for wheel and
`maturin develop` builds from `crates/rusty-bacnet/pyproject.toml`. Linking
needs the interpreter's shared library and its unversioned `.so` symlink, which
the job installs with `libpython3-dev`. The workflow sets
`PYO3_PYTHON=/usr/bin/python3`, so every PyO3 build uses the apt Python that
package matches, whatever else is on `PATH`, and the Rust tests don't depend
on the venv from the maturin step. Tests that call into Python start the
interpreter with `Python::initialize()` first, since nothing enables pyo3's
`auto-initialize`.

Use cargo-nextest 0.9.145 or later locally. Older releases on macOS could
mark unrelated passing tests as leaky (#751), and the configuration warns
about them.

### Samples

The sample programs in `examples/rust/samples` are workspace members with
`publish = false` (#1450). The root `Cargo.toml` lists each one in `members`,
so a new sample needs adding there: with a glob, a leftover directory without
a `Cargo.toml`, such as a renamed sample's ignored `target/`, would break every
cargo command. The samples share the workspace's `Cargo.lock`, so a version
bump or a new dependency of a `bacnet-*` crate needs no lock refresh, and every
`--workspace` run covers them: clippy, rustdoc and the tests, in CI and in the
[native tests](#native-tests-macos-and-windows). They stay out of
`default-members`, so a plain `cargo build` or `cargo test` at the root skips
them; `-p` picks one, as in `cargo run -p whois-scan -- --help`. A sample
inherits the workspace's license, which Cargo Deny checks for every member,
but not `[workspace.lints]`, since samples print to the terminal.

### Runner

Every Linux job runs on GitHub's `ubuntu-24.04` hosted runner, an x86_64 VM
with 4 vCPUs, 16 GB of RAM and about 14 GB free on `/`. A job runs on the VM
itself, not in a container, as the unprivileged `runner` user with
passwordless `sudo`, and installs what it needs (see [Tool pins](#tool-pins)).
Hosted runners take any PR, including one from a fork, which a self-hosted
runner shouldn't.

**Disk.** The largest job, Test, needs about 6 GB: about 3 GB of `target/` for
the every-feature test build, which the doctests and the CLI's feature-off
tests mostly reuse, 1 to 2 GB of Cargo registry (the downloaded crates and
their unpacked sources) and under 1 GB of toolchain. Clippy's `target/` is about 1 GB for the host, plus the Windows and
macOS check builds. Those `target/` sizes are from the same builds on macOS
arm64 with the workflow's build settings (October 2026); Linux builds without
debug info should come out about the same. So the jobs neither delete the image's
preinstalled SDKs nor move `target/` to another disk. Each build job ends with
a "Disk use and limits" step that logs `df`, the sizes of `target/`,
`CARGO_HOME` and `RUSTUP_HOME`, and the descriptor limits. If a job ever runs
short, remove the preinstalled SDKs no job uses (Android, .NET, GHC) in a step
before the build.

**Privileges and limits.** The Forgejo jobs ran as root in a Docker container
whose soft limit on open files was 1024. On the hosted runner they run as
`runner` on the VM's own network stack:

- No test needs root or a capability. The tests that open AF_PACKET sockets
  (`bacnet-integration-tests`' `ethernet_network_numbers`, `CAP_NET_RAW`) or
  need an isolated IPv6 link (`bacnet-transport`'s `ipv6_selected_link*`) are
  `#[ignore]`d and run only on a host set up for them. Otherwise the
  `ethernet`, `serial` and `serial-gpio` features are compiled and
  unit-tested without hardware; the serial-port listing test reads
  `/sys/class/tty`, which the VM has.
- The BACnet/SC hub capacity test needs about 2,100 descriptors and raises its
  own soft limit to that, which needs no privilege below the hard limit. The
  step above logs both limits.
- Two tests skip themselves on a host that doesn't deliver what they test:
  B/IP's `127.255.255.255` broadcast and B/IPv6's loopback multicast. Their
  output says when they skipped.

### Tool pins

The Linux jobs install their tools on the runner each time; there is no job
image.

- **Rust.** The runner image ships rustup. Each job installs the channel that
  `rust-toolchain.toml` pins, with the minimal profile plus the
  components that file lists, makes it the default, and uninstalls the
  image's own toolchains: rust-cache hashes every installed toolchain into its
  key, and the image's `stable` moves with image updates, which would start
  the jobs cold each time. The Clippy job adds the `x86_64-pc-windows-msvc` and
  `aarch64-apple-darwin` standard libraries for the per-crate default-features
  check (neither clippy nor rustdoc links, so nothing else is needed). The
  MSRV job adds the MSRV toolchain and sets `RUSTUP_TOOLCHAIN` to it.
- **Tools.** [`.github/ci-pins.env`](../.github/ci-pins.env) pins
  cargo-nextest, cargo-deny, cargo-audit and maturin, each with the SHA-256 of
  its Linux x86_64 release archive, and the MSRV and the native tests' Python
  version. [`scripts/ci/install-tools.sh`](../scripts/ci/install-tools.sh)
  downloads the tools a job names, checks each archive against its digest
  before unpacking it, and puts the binaries in `~/.cargo/bin`.
  `native-tests.yml` reads the cargo-nextest, maturin and Python versions from
  the same file.
- **apt.** Each job names its packages in `APT_PACKAGES` (`libpcap-dev` for
  Clippy, Test and MSRV; `python3-venv` and `libpython3-dev` for the Python
  job) and installs only those the image lacks, so a job whose packages are
  all there skips `apt-get update`. The image already has the C toolchain,
  `pkg-config`, CMake, Perl, `file`, `jq`, Python 3.12 and `openssl`. Nothing
  needs libudev: `serialport` builds without it.

The Lint job's "Check the pins" step fails when:

- a line of `.github/ci-pins.env` isn't a comment, blank, or `NAME=value` with
  a plain value, or a name is set twice;
- a `*_SHA256` value isn't 64 lowercase hex digits;
- `rust-toolchain.toml`'s channel isn't an exact release;
- `RUST_MSRV` differs from `Cargo.toml`'s `rust-version` or from
  `scripts/ci/check-msrv.sh`'s default toolchain.

**Bumping a pin:**

- **Toolchain:** `rust-toolchain.toml` alone; both workflows install from it.
- **MSRV:** `Cargo.toml`'s `rust-version`, `RUST_MSRV` and
  `scripts/ci/check-msrv.sh` together.
- **A tool:** its `*_VERSION` and `*_SHA256` together. The digest is of the
  archive the comment above it names:
  `curl -sSfL <url> | sha256sum`.

The [release](#release) reads the same file for pins of its own for its
[builds](#builds): the manylinux2014 images' digests, rustup-init's version
and digests, and libpcap's version and digest. The same format check covers
them. Its builds install maturin from
`scripts/release/maturin-requirements.txt`, by sha256, at the
`MATURIN_VERSION` here.

### Caches

GitHub gives the repository 10 GB of Actions cache. Past that it evicts the
least recently used entries, which can be `dev`'s current ones, and it evicts
any entry unused for seven days. On 4 October 2026 the caches had reached
12.3 GB, mostly entries no run would restore again (#1471).

- **Saves.** Only runs on `dev` save Rust caches: merges, the weekly run and
  manual runs there. PR runs only restore them.
- **Pruning.** After a green run on `dev`, each workflow's **Prune caches**
  job runs [`scripts/ci/prune-caches.sh`](../scripts/ci/prune-caches.sh) with
  `actions: write`. It keeps the two newest rust-cache entries of each family
  (one job on one OS: the key without its environment and lock hashes, such
  as `v0-rust-test-Linux-x64`) and every other entry on `dev`, such as
  setup-node's, and deletes the rest: older Rust entries, and every entry on
  another ref. It logs each deletion with its key, ref, size and reason, and
  the total before and after.
- **Out-of-order runs.** Runs on `dev` don't always finish in merge order,
  so the newest entry of a family can come from an older merge. Only the run
  for `dev`'s current head prunes (an older one logs that and stops), and
  keeping two entries per family leaves the current head's in place even then. To see what it would delete, with `gh`
  signed in: `bash scripts/ci/prune-caches.sh --dry-run jscott3201/rusty-bacnet`.
- **Budget.** One set of Rust caches is about 2.3 GB: the four native jobs'
  took 1.26 GB on 4 October 2026, and the four Linux jobs' about 1 GB, going
  by the same jobs' caches on Forgejo (Clippy 320 MB, Test 300 MB, MSRV
  245 MB, Python 170 MB). setup-node's cache on `dev` adds 110 MB. Keeping
  two sets makes the steady state about 4.7 GB. A merge that changes
  `Cargo.lock` or the toolchain saves a third set, which the prune after it
  removes, so the peak is about 7 GB, plus 110 MB for each PR that changed
  `website/**` since the last prune. That leaves about 3 GB of headroom.

## Native tests (macOS and Windows)

[`.github/workflows/native-tests.yml`](../.github/workflows/native-tests.yml)
runs the tests, clippy and rustdoc natively on GitHub-hosted macOS
(`macos-latest`, Apple Silicon) and Windows (`windows-latest`, the MSVC
toolchain) runners (#950). Each platform has two jobs, which run in parallel:

- **Tests (macOS arm64)** and **Tests (Windows x86_64)**: the workspace tests,
  the stack guard and the doctests, which share one test build;
- **Lint and Python (macOS arm64)** and **Lint and Python (Windows x86_64)**:
  clippy, rustdoc, the CLI's default-feature tests, and the Python bindings
  with their Python and Rust tests.

**Native OK** waits for all four and passes only when every one succeeded. It
runs even when a job failed or was cancelled, so it always reports, like
`ci.yml`'s `CI OK`. With `CI OK`, it is one of the two checks the merge gate
reads.

**Trigger.** Every PR to `dev` or `main`, every push to them (merges), and a
manual dispatch. Tag pushes don't run it.

**Steps.** `NATIVE_FEATURES` is the `features=` list in
[`scripts/ci/local-macos.sh`](../scripts/ci/local-macos.sh), which the
workflow reads: every optional feature except the Linux-only `serial` and
`ethernet`, including per-crate ones such as `bacnet-endpoint/sc-tls`. Windows
also leaves out `bacnet-cli/pcap`, which needs the Npcap SDK. The Tests jobs
run:

```bash
cargo nextest run --workspace --exclude rusty-bacnet --locked --features "$NATIVE_FEATURES" --profile ci
# stack guard (#953): STACK_GUARD_TESTS again with 1 MiB thread stacks, after
# `ulimit -s 1024` on macOS so the CLI tests' `bacnet` processes get a 1 MiB
# main thread, as on Windows
RUST_MIN_STACK=1048576 cargo nextest run --workspace --exclude rusty-bacnet --locked --features "$NATIVE_FEATURES" --profile ci -E "$STACK_GUARD_TESTS"
cargo test --doc --workspace --exclude rusty-bacnet --locked --features "$NATIVE_FEATURES"
```

The Lint and Python jobs run:

```bash
cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked --features "$NATIVE_FEATURES" -- -D warnings
cargo clippy -p rusty-bacnet --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude rusty-bacnet --no-deps --locked --document-private-items --features "$NATIVE_FEATURES"
RUSTDOCFLAGS="-D warnings" cargo doc -p rusty-bacnet --no-deps --locked --document-private-items
cargo nextest run -p bacnet-cli --locked --profile ci   # the CLI's feature-off tests
# Python $PYTHON_VERSION from actions/setup-python, in a fresh venv; the
# versions come from .github/ci-pins.env
python -m pip install "maturin==$MATURIN_VERSION"
maturin develop -m crates/rusty-bacnet/Cargo.toml --locked
python -m unittest discover -s crates/rusty-bacnet/tests
cargo nextest run -p rusty-bacnet --locked --profile ci
```

The CLI's default-feature tests build `bacnet-cli` with its default features,
which the Tests job's build can't reuse, so they run in the shorter job.
PyO3 builds link setup-python's interpreter (`PYO3_PYTHON`), not the venv's;
the Tests jobs set up Python too, because the conformance ledger test runs
`python3`. Within a job every step runs even when an earlier one failed, so
one run reports each failure. `STACK_GUARD_TESTS` (in the workflow's `env`)
selects every server, client, endpoint, integration and CLI test, the
benchmark SC mTLS tests and bacnet-transport's BACnet/SC tests; the guard step
runs `--no-run` first because rustc reads `RUST_MIN_STACK` too, and adds about
two minutes to each Tests job. The per-crate default-feature checks
(`scripts/ci/check-default-features.sh`) aren't here: `ci.yml`'s Clippy job
runs them for Windows and macOS too, cross-checked (see
[Local checks](#local-checks)).

Before anything else, each Windows job stops the Microsoft Compatibility
Appraiser (#1003). Its `CompatTelRunner.exe` can take all four of the runner's
CPUs for seconds at a time, enough to blow a test's timing budget. The runner
image already disables the scheduled tasks that run it (those in
`\Microsoft\Windows\Application Experience\`). During a job, the Inventory and
Compatibility Appraisal service (`InventorySvc`) starts it instead, several
times, with its software-inventory module (`-m:aeinv.dll`). A diagnostic run
with process-creation auditing caught three launches in one job, the last of
which had used 53 s of CPU in five minutes; with this step, a second run had
none (October 2026, image windows-2025-vs2026). The step disables and stops that
service, disables any task that runs `CompatTelRunner.exe` in case a newer
image re-enables one, stops any running copy, and logs what it found. It
takes about two seconds and never fails the job.

**Toolchain and tools.** Both runner images ship rustup. The workflow reads
the channel and components from `rust-toolchain.toml`, so it has no toolchain
version to keep in step, and installs them with rustup's minimal profile. The
file's default profile would add `rust-docs`, thousands of small files that
took the step to about a minute on Windows, and up to three; without them it
takes 10 to 20 seconds. cargo-nextest is a prebuilt binary from
`taiki-e/install-action`, which checks the download against its own manifest,
and maturin comes from PyPI; their versions, and Python's, come from
[`.github/ci-pins.env`](../.github/ci-pins.env), as `ci.yml`'s do.
aws-lc-sys, which `sc-tls` pulls in, builds with the images' own C tools: on
Windows, MSVC with the NASM and CMake already on `PATH`. The SC tests make
certificates with the runner image's `openssl`.

**Efficiency.** The workflow can only read the repository
(`permissions: contents: read`; Prune caches alone can also write Actions
caches), and each job stops after 60 minutes. A newer push to a PR cancels
its running run. On `dev` each commit gets its own concurrency group, keyed by
its SHA, so no run is cancelled or replaced while pending and every merge gets
its own result. `Swatinem/rust-cache` keeps dependency builds, keyed per job
and OS on the toolchain, `Cargo.lock`, the manifests and `NATIVE_FEATURES`.
Only `dev` saves it, and only from a successful job, so a failed or cancelled
run never leaves a partial cache that later runs would restore by exact key.
GitHub lets a PR's run restore the default branch's (`dev`) cache, so every PR
starts from the last good `dev` build; see [Caches](#caches) for pruning. The
cache holds dependencies only, so most of a job is compiling the workspace and
its tests. In October 2026, with the jobs split, a run took about 11 to 12
minutes, cold or warm. The Windows Tests job, the usual floor, took 10 to 11.5
minutes; the macOS one 4.6 to 10.2, as macOS hosts vary widely in speed; the
Lint and Python jobs 6 to 8 minutes warm and 8 to 11 cold. With one job per
platform a run had taken a median 18.4 minutes, Windows being the slowest.

Two Windows build speedups were measured and left out. A ReFS Dev Drive for
the target directory, `CARGO_HOME` and `RUSTUP_HOME` made the test build two
to three minutes slower: Defender's real-time scanning is already off on the
runner image, with `C:\` and `D:\` excluded, and `D:` is a local NVMe disk, so
the virtual disk only added a layer. Linking with `rust-lld` instead of
MSVC's `link.exe` saved no more than the spread between runner VMs (the same
build took 3.6 to 5.1 minutes on different VMs).

**macOS capacity.** GitHub's free plan runs at most 5 macOS jobs at once
across the account, and the native tests already reach that cap: over 400
runs on 3 and 4 October 2026, when every pushed branch ran them, a macOS job
waited a median 0.1 minutes to start, 7.3 at the 90th percentile and up to 28.
Splitting macOS gives each run two macOS jobs and about 12% more macOS
minutes. Replaying those runs' arrival times against the caps, with each job's
time drawn from their history, the split came out ahead at 4 October's load
(median 10.9 minutes to a result against 13.0; 90th percentile 11.8 against
15.3) and at the median over both days (11.4 against 13.7). It queued longer
only in bursts of about 20 runs an hour, which fill the cap with either
layout: over both days its 90th percentile was 24.7 minutes against 22.9, and
over the busiest seven hours 36 against 29.

**Portable tests.** What the first Windows and macOS runs showed (#950):

- Text files check out with LF line endings on every OS (`.gitattributes`);
  Windows checkouts would otherwise get CRLF from `core.autocrlf`.
- Don't stand a loopback address in for a broadcast address. Windows reports
  delivery to `127.0.0.1` as unicast, and B/IP then drops an
  Original-Broadcast-NPDU. Drive a BBMD with what may arrive by unicast
  (Distribute-Broadcast-To-Network, Forwarded-NPDU), or call the handler with
  `Delivery::Broadcast`.
- Don't rely on sending to `255.255.255.255`: GitHub's macOS runners refuse it
  with `EHOSTUNREACH`.
- Compare `io::ErrorKind`, or the error the OS gives for the same call, not
  Unix error text.
- Stacks are smaller on Windows: the main thread gets 1 MiB (8 MiB on Linux
  and macOS), so `#[tokio::main]` binaries box their large futures, as
  `bacnet` does. Test threads get 2 MiB everywhere, and debug-build async
  fixtures can fill that. A debug build gives every future an async fn awaits
  at least one stack slot of its own, sized to the whole future, in that fn's
  poll frame, so a fixture or startup path that awaits many large futures has
  a large frame. Create such a future in a helper that boxes it
  (`boxed(|| step()).await`, as the server, SC and fixture code does since
  #953); `Box::pin(step())` in the caller still builds the full-size temporary
  in the caller's frame. The stack guard step catches regressions; to see how
  close a test is, bisect `RUST_MIN_STACK` (or `ulimit -s` for a binary's main
  thread). On nightly, `-Zprint-type-sizes` gives future sizes, and
  `-Cremark=prologepilog` gives each function's frame size.
- Another socket may bind `127.0.0.1:P` beside a wildcard `0.0.0.0:P` on
  Windows unless the first socket set `SO_EXCLUSIVEADDRUSE`, which an
  ephemeral B/IP or B/IPv6 socket now does. Linux refuses that bind. macOS
  refuses a plain one, but not one from a socket that sets `SO_REUSEADDR`, and
  has no option to prevent it.
- `localhost` resolves to `::1` first on Windows, and a refused loopback
  connect takes about 2 seconds there. The SC dialer races a host's
  addresses (RFC 8305 style), so a dial to `localhost` against an IPv4-only
  listener costs the 250 ms attempt delay rather than 2 seconds; a test whose
  timing depends on a dial must allow for it.

**Reading a run** (either workflow):

```bash
gh pr checks <n> -R jscott3201/rusty-bacnet   # every check on a PR's head
gh run list -R jscott3201/rusty-bacnet --workflow native-tests.yml --branch <branch>
gh run view -R jscott3201/rusty-bacnet <run id> --log-failed
gh workflow run native-tests.yml -R jscott3201/rusty-bacnet --ref <branch>  # run by hand
```

## Local checks

Use the Rust release that `rust-toolchain.toml` pins, which rustup selects in
the checkout. The [native tests](#native-tests-macos-and-windows) run the
macOS tests, clippy and rustdoc on every PR, so a local macOS run is
optional: a quicker check before pushing changes that can affect macOS
(transports, sockets, TLS, platform `cfg`, build scripts, dependencies). It
isn't merge evidence.

```bash
bash scripts/ci/local-macos.sh          # lint, clippy, rustdoc, macOS tests
bash scripts/ci/local-macos.sh --quick  # lint, clippy and rustdoc only
```

`serial` and `ethernet` are Linux-only features, so macOS uses every other
optional feature. The native-tests workflow reads the same list from the
script. That includes per-crate features such as
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
Clippy runs four ways:

- the workspace with every feature;
- the PyO3 crate on its own;
- `bacnet-cli` with no default features (without the TUI);
- each published crate alone with default features, plus the `no_std` build of
  `bacnet-types` (`scripts/ci/check-default-features.sh`). This also runs
  rustdoc, which is how docs.rs builds, and a rustdoc-only run of `bacnet-cli`
  without the TUI.

The last catches code that compiles only when another crate's feature unifies
in. With no arguments it checks the host; given target triples, it checks
those, side by side in one cargo run per crate. CI's Clippy job passes
`DEFAULT_FEATURES_TARGETS`: Linux, `x86_64-pc-windows-msvc` and
`aarch64-apple-darwin`, whose platform `cfg`s compile different code (#981).
Neither clippy nor rustdoc links, and no C code builds with default features,
so another target needs only `rustup target add`, not cargo-xwin or zig.

Rustdoc's every-feature run and the PyO3 crate's run pass
`--document-private-items` (#1164), so a broken intra-doc link in the docs of
a private or `pub(crate)` item fails the gate too. The flag still reports a
public item whose docs link to a private item
(`rustdoc::private_intra_doc_links` fires with or without it), so the
every-feature run replaces the public-only run rather than adding a second
one. Every module of the PyO3 crate is private, so without the flag rustdoc
would check none of its docs. The per-crate default-features run and the
feature-off rustdoc runs of `check-default-features.sh` (`bacnet-types` without
`std`, `bacnet-cli` without `tui`) pass the flag too (#1192), so private items
that exist only in one feature configuration are covered; the run takes about
2 s longer on the host.

The individual gates are also runnable anywhere. `FEATURES` is
`LINUX_FEATURES` from `ci.yml`, without the serial and ethernet entries on macOS:

```bash
FEATURES=$(sed -n 's/^  LINUX_FEATURES: //p' .github/workflows/ci.yml)
cargo fmt --all --check
cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked --features "$FEATURES" -- -D warnings
cargo clippy -p rusty-bacnet --all-targets --locked -- -D warnings
cargo clippy -p bacnet-cli --no-default-features --all-targets --locked -- -D warnings
bash scripts/ci/check-default-features.sh   # the host; or pass target triples, as CI does
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude rusty-bacnet --no-deps --locked --document-private-items --features "$FEATURES"
RUSTDOCFLAGS="-D warnings" cargo doc -p rusty-bacnet --no-deps --locked --document-private-items
cargo nextest run -p bacnet-cli --locked   # the CLI's feature-off tests
cargo nextest run -p bacnet-cli --no-default-features --locked   # without the TUI
cargo nextest run -p rusty-bacnet --locked # the PyO3 crate's Rust tests
bash scripts/ci/check-file-size.sh
bash scripts/ci/test-check-no-secrets.sh && bash scripts/ci/check-no-secrets.sh
python3 scripts/ci/test-check-msrv.py
python3 scripts/check_ledger_style.py && python3 scripts/check_ledger_links.py
python3 -m unittest discover -s scripts/release
python3 -m unittest discover -s scripts -p 'test_changelog.py'
python3 scripts/changelog.py check
python3 -m unittest discover -s scripts -p 'test_ledger_*.py'
actionlint .github/workflows/*.yml          # after editing a workflow
```

`changelog.py check` validates the [changelog fragments](../changelog.d/README.md)
and fails if `CHANGELOG.md`'s `[Unreleased]` section lists entries itself, so a
PR that edits it directly fails the lint job.

The no-secret scanner reports stable opaque path IDs and line numbers, never
paths or matching text, because filenames can contain credentials too. Compare
a suspected path locally with `printf '%s' "$path" | git hash-object --stdin`.
Run the file-size gate in its default strict mode, without `CHECK_FILE_SIZE_WARN=1`.

`scripts/ci/check-msrv.sh --linux-native` needs a native Linux GNU host with
the MSRV toolchain (`RUST_MSRV`) installed, Python 3, a C toolchain, `pkg-config`, `libpcap-dev`,
`cmake`, `perl`, `file` and `ldd`. It never installs tools or skips features.
CI runs it on PRs to `main`; on a Mac, rely on that job.

## Merge evidence

Before merging a PR:

- `CI OK` and `Native OK`, the two required checks, are green on the PR for
  the exact head SHA being merged;
- existing review and merge-authorization rules are met.

A `local-macos.sh` pass is optional and isn't needed to merge.

A check that was not run, failed or does not apply is never reported as passed.
Audit and deny read mutable advisory databases, so their result for a `main`
merge comes from that PR's run, not an older one. On a PR from `dev` to
`main`, the head commit also carries the `CI OK` of `dev`'s push run, which
covers only the Lean jobs, so check that the `pull_request` run's `CI OK`,
the one with MSRV and audit and deny, is green. The release's
[CI gate](#ci-gate) requires the CI run of the tag's own push, which runs
them.

## Release

[`.github/workflows/release.yml`](../.github/workflows/release.yml) builds,
tests and publishes each release on GitHub-hosted runners (#943, #1472). Every
artifact is built on a runner of its own platform and architecture, with that
platform's own toolchain, and run there before anything is published. GitHub
Pages publication remains the manual
[`docs-pages.yml`](../.github/workflows/docs-pages.yml) dispatch.

### Trigger and dry run

- **Tag.** Pushing a `v*` tag to GitHub runs the whole release.
- **Dry run.** A manual dispatch is a dry run by default (`dry_run` is true). It
  builds, checks and smoke-tests every artifact, keeps them as workflow
  artifacts, plans the publish steps read only (see
  [Publish plan](#publish-plan-dry-run)) and publishes nothing:

  ```bash
  gh workflow run release.yml -R jscott3201/rusty-bacnet --ref dev
  ```

  `dry_run=false` is accepted only on a `v*` tag, where it runs that tag's
  release again in a new run (see
  [Re-running a partial release](#re-running-a-partial-release)).
- **Pull request.** A PR to `dev` or `main` that changes what the release
  builds with runs a dry run, so a release change is tested before it merges:
  the workflow itself, `.github/ci-pins.env`, `scripts/release/**`,
  `Cargo.toml`, `Cargo.lock`, `crates/*/Cargo.toml`, `rust-toolchain.toml`,
  `crates/rusty-bacnet/pyproject.toml` and `scripts/changelog*.py`. Not
  `changelog.d/`, which nearly every PR changes. A newer push to the PR
  cancels the older dry run. The check isn't required for merging.

A dry run's notes come from the workspace version's `CHANGELOG.md` section if
it has one, otherwise from the section the waiting `changelog.d/` fragments
would make, which may be empty; `changelog.py assemble --output` writes that
into a copy, so the checkout is left alone. A dry run uses no secret, never
deploys to the `release` environment and writes nothing, so a fork's PR runs
it too.

To release:

0. Once, before the first release from this workflow: on pypi.org, under
   rusty-bacnet's Publishing settings, add a GitHub trusted publisher with
   owner `jscott3201`, repository `rusty-bacnet`, workflow `release.yml` and
   environment `release`, then remove the one that names `ci.yml`. The
   [PyPI trusted publishing](#secrets-and-environment) job stops a release
   before crates.io if this isn't done.
1. Set the workspace version, assemble the version's `CHANGELOG.md` section
   from the fragments, add release highlights by hand under the new heading if
   the release has any, and merge:

   ```bash
   python3 scripts/changelog.py preview        # what the section will hold
   python3 scripts/changelog.py assemble --version 0.12.0 [--date 2026-10-02]
   ```

   `assemble` adds `## [0.12.0] - <date>` below `[Unreleased]`, with the
   entries grouped by heading and ordered by issue number, and deletes the
   fragments it used. Each entry ends with a link to the GitHub commit that
   brought its fragment into dev, found along the first-parent history, so run
   it on a branch cut from dev's tip with full history (#1188); `preview` shows
   the same links. A tag fails if any fragment is still waiting.
2. Optionally, dispatch a dry run on the release branch first: it runs
   everything the release does short of publishing.
3. Tag a commit on `main`'s or `dev`'s first-parent history (a merge commit,
   not one inside a merged branch), once its CI has passed:

   ```bash
   git tag -a v0.12.0 -m "Rusty BACnet 0.12.0"
   git push origin v0.12.0
   ```

The tag push also starts CI's heavy jobs on the tagged commit, and the release
waits for them (see [CI gate](#ci-gate)).

### Jobs

| Job | What it does |
| --- | --- |
| Validate | Runs the release script tests (`scripts/release/test_*.py`, `scripts/test_changelog.py`). Checks that every publishable crate has the workspace version and, for a tag, that the tag is `v<version>` and the commit is on `dev`'s or `main`'s first-parent history (`git rev-list --first-parent`), so a commit inside a merged PR's branch doesn't qualify. For a tag, checks that no `changelog.d/` fragment is left unassembled. Extracts the notes with `changelog_notes.py` and writes `THIRD-PARTY-NOTICES`. |
| CI gate | `ci_gate.py` on the release commit (a PR's head on a PR's dry run). On a tag it waits for the CI run the tag's push started; a dry run checks once and only warns. See [CI gate](#ci-gate). |
| Crates and sdist | `cargo publish --workspace --dry-run --locked`, which packages every publishable crate and builds each against the others as published. Then `cargo package` for the `crates` artifact, and `maturin sdist`. |
| Build (linux-x86_64, linux-aarch64, macos-x86_64, macos-arm64, windows-x86_64) | The wheels for CPython 3.11 to 3.14 (`PYTHONS`) and the CLI, on each platform's own runner. See [Builds](#builds). |
| Check the artifacts | `check_artifacts.py` over every file, then the `release-assets` artifact: what the publish jobs upload. See below. |
| Smoke test (Linux x86_64, Linux aarch64, macOS arm64, macOS x86_64, Windows x86_64) | Each platform's wheels and CLI, run on that platform. See [Smoke tests](#smoke-tests). |
| Publish plan (dry run) | Dry runs only, read only: `release_api.py plan` and `publish_crates.sh --dry-run`. See [Publish plan](#publish-plan-dry-run). |
| PyPI trusted publishing | Releases only, in the `release` environment, as soon as Validate passes: exchanges the job's OIDC token for a PyPI upload token, which proves PyPI's trusted publisher matches this workflow. The minted token is masked at once, never printed and discarded. See [Secrets and environment](#secrets-and-environment). |
| GitHub draft | `release_api.py stage`: makes the tag's GitHub draft hold exactly the `release-assets` files and their `SHA256SUMS`. See [Draft, then publish](#draft-then-publish). |
| Publish to crates.io | `publish_crates.sh`: one multi-package `cargo publish --no-verify` of the crates whose version isn't on crates.io yet. Cargo orders them and waits for the index. |
| Publish to PyPI | `pypa/gh-action-pypi-publish` with trusted publishing: the wheels and the sdist. |
| GitHub release | `release_api.py publish`: publishes the staged draft, unchanged. |

**Check the artifacts.** `check_artifacts.py` checks that there is one wheel
per Python and platform with the right tags, version (the workspace version
in PEP 440 form) and extension module, and `THIRD-PARTY-NOTICES` in each wheel
and the sdist. For every binary it checks the architecture and linkage: ELF
with nothing above glibc 2.17 (`objdump -T`) and no dynamic libpcap; Mach-O
with the tag's minimum macOS, a code signature on arm64, only the expected
libraries, and only Python's C API left to a flat lookup (`llvm-objdump`);
PE with only the expected DLLs (`llvm-readobj`). Output that parses to
nothing fails (no bind table, no Python lookups in an extension module, no
`kernel32.dll` import). `llvm-objdump` and `llvm-readobj` come from the
pinned toolchain's `llvm-tools`.

**Order.** The publish jobs run only for a tag, and only after Validate, the
CI gate, the artifact check and every smoke test passed. They run one at a
time in the order above, so a failure stops the jobs after it. The GitHub
draft comes first because it is the one reversible step: it shows that GitHub
takes the release before crates.io and PyPI, which can't be undone. crates.io
also waits for the PyPI trusted publishing check, so a PyPI publisher that
doesn't match stops the release before anything is published. The draft
is published last, so the release page and `releases/latest` show the
release only once its crates and wheels are out.

Release builds use no Rust cache: every build starts from the pinned
toolchain and `Cargo.lock`, and nothing a PR's run saved can reach a tag's
build.

#### Runners

| Artifacts | Runner | Toolchain |
| --- | --- | --- |
| Linux x86_64 wheels and `bacnet-linux-amd64` | `ubuntu-24.04` | the manylinux2014 image: CentOS 7, glibc 2.17, GCC 10 |
| Linux aarch64 wheels and `bacnet-linux-arm64` | `ubuntu-24.04-arm` | the manylinux2014 image for aarch64 |
| macOS x86_64 wheels and `bacnet-macos-amd64` | `macos-26-intel` | Xcode's clang and linker |
| macOS arm64 wheels and `bacnet-macos-arm64` | `macos-26` | Xcode's clang and linker |
| Windows x86_64 wheels and `bacnet-windows-amd64.exe` | `windows-2025` | MSVC, with the image's NASM for AWS-LC |

Nothing is cross-compiled or emulated. The labels name an image version, not
`-latest`, so a move to a newer image is a reviewed change. `macos-26-intel`
is GitHub's newest Intel macOS image (`macos-15-intel` is the other one
left); if GitHub retires its Intel images, the macOS x86_64 build can move to
`macos-26` with `--target x86_64-apple-darwin`, which Xcode builds natively,
but its smoke test would then have no runner.

#### What is and isn't tested

Every file gets the static checks above, and the smoke tests run every wheel
and CLI on its own platform: Linux on both architectures, on Ubuntu 24.04 and
in CentOS 7 (glibc 2.17), macOS on Apple Silicon and Intel, and Windows. The
Python suite runs against the installed cp312 wheel on both Linux
architectures; on macOS and Windows, native tests run it against each PR's
own build. These tests show that the files load and work on those hosts.
They say nothing about hardware, or about older macOS and Windows versions
than the runners'.

### CI gate

The release needs CI to have passed on its commit, read from GitHub's API by
[`scripts/release/ci_gate.py`](../scripts/release/ci_gate.py): the commit's
workflow runs (`GET /repos/{o}/{r}/actions/runs?head_sha=<sha>`), and for each
run of `ci.yml` and `native-tests.yml` the check runs of its check suite
(`GET /repos/{o}/{r}/check-suites/{id}/check-runs?filter=latest`). The job
token needs `actions: read` and `checks: read`.

- **CI.** On a release, the `ci.yml` run that the tag's push started (event
  `push`, `head_branch` the tag, `head_sha` the commit; the newest if it was
  re-run) must have succeeded: its `CI OK`, `MSRV (Linux native)` and `Cargo
  Audit + Deny` check runs all `success`. CI runs those two heavy jobs on
  tags, so that run checks the commit with that day's advisory databases, and
  no other run, however heavy, stands in for it. If it skipped them, the gate
  fails at once.

  A dry run has no tag, so there the gate takes the newest `ci.yml` run on the
  commit that ran MSRV and audit-deny. CI runs them on tags, pushes to `main`,
  PRs to `main`, the weekly run and manual runs, and skips them on PRs to
  `dev` and pushes to `dev`, whose `CI OK` passes without them. A commit can
  therefore carry several `CI OK` check runs: a `dev`→`main` PR's head has
  `dev`'s lean push run and the PR's heavy run. Only a run that ran the heavy
  jobs counts, so a lean `CI OK` never stands in for MSRV, audit and deny. A
  run that skipped both, or finished without either, is lean.
- **Native.** The newest `native-tests.yml` run on the commit must have
  `Native OK` `success`. Native tests don't run on tags, so the tagged commit
  must have come through a push to `dev` or `main`, which runs them.

Only this repository's runs count, not a fork's pull request runs, and only
check runs created by GitHub Actions. Within a run the latest check run of
each name counts, so a re-run of failed jobs replaces the attempt it re-ran.
Of several runs, the newest (by the start of its latest attempt) counts, so
an older success can't hide a newer failure. `test_ci_gate.py` reads both
workflow files and fails if a job name the gate relies on, or `ci.yml`'s
trigger on `v*` tags, is gone, so a rename shows in the PR that makes it, not
after a tag's 60-minute wait.

On a tag, the gate polls every 30 seconds for up to 60 minutes while the run
that counts is still going or doesn't exist yet. It fails at once when a
named check run finished other than `success`, or is missing from a finished
run, and its message says to re-run that run's failed jobs if the failure was
transient. At the deadline it fails with what it saw. A dry run checks once
and only warns. The gate runs alongside the builds, and every publish job
needs it.

### Smoke tests

Each Smoke test job downloads its platform's `wheels-<platform>` and
`cli-<platform>` artifacts, the same files `release-assets` holds, and sets up
CPython 3.11 to 3.14 with `actions/setup-python`. The jobs are independent:
one failing doesn't cancel the others.

- **Wheels.** Each wheel, installed with `pip --no-index --no-deps` into a
  fresh venv of its own CPython, runs
  [`wheel_smoke.py`](../scripts/release/wheel_smoke.py): the installed version
  is the release's; `list_serial_ports()` returns a list of port names, which
  on macOS goes through IOKit and CoreFoundation, both of which must then be
  loaded, and on Windows through SetupAPI; and a loopback round trip with the
  public API, where a `BACnetServer` on 127.0.0.1 serves an analog input and
  an analog value and a `BACnetClient` reads the input's present value, reads
  it and its name with ReadPropertyMultiple, writes the value's present value
  at priority 8 and reads it back.
- **CLI.** [`cli_smoke.sh`](../scripts/release/cli_smoke.sh): `--version` must
  print `bacnet <version>`, `--help` runs, and the README quickstart `read` and
  `--json readm` run against the README server on the cp312 wheel. On Linux,
  `capture --read` also decodes a one-packet pcap file, through the static
  libpcap and its filter compiler, without needing capture privileges. The
  macOS and Windows builds have no packet capture.
- **Python suite** (Linux): `python -m unittest discover -s
  crates/rusty-bacnet/tests` against the installed cp312 wheel.
- **glibc 2.17** (Linux):
  [`smoke_glibc217.sh`](../scripts/release/smoke_glibc217.sh) runs the cp312
  wheel's `wheel_smoke.py` and the CLI's `cli_smoke.sh`, capture included, in
  the manylinux2014 image the artifacts were built in, whose CentOS 7 has
  glibc 2.17: the oldest system the Linux artifacts support.

**Reading a failed smoke test.** Each job is one platform. In **Wheels, each
CPython**, each wheel's output is a log group named after the wheel, and the
last one shows which wheel and which check failed: the install, the import,
the version, the serial port listing or the round trip. On macOS, an abort
with "symbol not found" or "Library not loaded" points at the links that the
artifact check lists. **CLI** shows `cli_smoke.sh`'s output, with the Python
server's log if it didn't start. A long wait for a runner, most often the
Intel macOS one, shows as a queued job, not a failure.

A failed smoke test publishes nothing. A bug in an artifact needs a new
commit, released as a new version.

### Draft, then publish

GitHub releases in this repository are immutable once published: assets can't
be added, replaced or deleted, and the tag can't be used again.
[`release_api.py`](../scripts/release/release_api.py) therefore builds each
release as a draft and publishes it last. The GitHub draft job runs `stage`:

1. Check that the tag exists and points at the release commit.
2. `GET /repos/{o}/{r}/releases` (all pages), matching `tag_name`, because
   `/releases/tags/{tag}` doesn't return drafts. GitHub lists drafts only to a
   token that can write, so the job has `contents: write`. A published
   release is only checked, read only.
3. `POST /repos/{o}/{r}/releases` with `draft: true`, `target_commitish:
   <commit>` and the notes, unless a draft exists. A pre-release version
   (`-` in the tag) makes a pre-release.
4. Make the draft hold exactly the `release-assets` files: delete what an
   interrupted upload left (any asset not in state `uploaded`), every asset
   that isn't one of the files, every copy of a name that appears twice, and
   every asset whose digest differs from this run's file; then
   `POST uploads.github.com/.../releases/{id}/assets?name=...` for each file
   the draft lacks.
5. `SHA256SUMS` for those files, uploaded the same way; an outdated one is
   deleted first.
6. The final check (below), on a fresh `GET` of the draft.

It writes the draft's id and the sha256 of its `SHA256SUMS` as job outputs.
After crates.io and PyPI, the GitHub release job runs `publish` with both: the
tag's release must be that draft, this run's files must give the same
`SHA256SUMS`, and the draft must pass the final check again. Then
`PATCH /repos/{o}/{r}/releases/{id}` with `draft: false` and `make_latest:
"legacy"` is the only write. `legacy` has GitHub pick the latest release by
date and version, so a backport published after a newer release doesn't
become the latest. A publish without both staged values, or with an empty
one, publishes nothing: the step checks, and so does `release_api.py`.

- **Final check.** The last step before the irreversible publish. The raw
  asset list, before any filtering by state, must hold exactly the expected
  names, once each, with no entry other than `uploaded`. Each asset's size
  must match, and its reported `digest` (`sha256:<hex>`) must equal the
  sha256 of this run's file (for `SHA256SUMS`, of the text this run
  computed). An asset without a digest is downloaded and hashed.
- **Resuming.** A draft left by an earlier attempt keeps its notes, but only
  if its `target_commitish` is the release commit: a draft made for another
  commit stops the run with a message to delete it. Assets it already holds
  with this run's bytes aren't sent again.
- **Published.** The script never uploads to or deletes from a published
  release. It checks that every asset and `SHA256SUMS` are there and that each
  asset matches `SHA256SUMS`, and fails with an explanation otherwise.
- **Retries.** Reads, the final `PATCH` and deletes retry on 5xx and network
  errors, including a truncated response (`http.client.HTTPException`, such
  as `IncompleteRead`). Deletes treat 404 as done, so a retried delete
  succeeds. A `POST` doesn't retry: after an uncertain upload failure, or
  GitHub's 422 `already_exists`, the script lists the draft's assets again
  and accepts the asset if it's complete and its digest matches, or deletes
  it and sends the file again. A failed create looks for the draft before
  trying again.
- **Downloads.** GitHub serves a draft's assets only through the API asset URL
  with `Accept: application/octet-stream`. The token goes in an unredirected
  header, so the redirect to storage never carries it.

#### Publish plan (dry run)

The Publish plan job runs `release_api.py plan` for the tag `v<version>`,
which makes no write: it checks the tag, finds the release, checks a
published one and downloads its smallest asset, or prints the deletions and
uploads `stage` would make (or warns that a draft for another commit would
stop it). Its token can only read, so it doesn't see drafts. While the
workspace version is already released, it reports what the published release
lacks as a warning. `publish_crates.sh --dry-run` then lists the crates whose
version isn't on crates.io yet.

### Artifacts

- `release-assets`: what the publish jobs upload, which the GitHub release
  also gets with a `SHA256SUMS` file:
  - `bacnet-linux-amd64` and `bacnet-linux-arm64`, with BACnet/SC and packet
    capture;
  - `bacnet-macos-amd64`, `bacnet-macos-arm64` and `bacnet-windows-amd64.exe`,
    with BACnet/SC (no packet capture, as in 0.11.0);
  - `rusty_bacnet-<version>.tar.gz`, the sdist;
  - twenty wheels, `rusty_bacnet-<version>-cp3XY-cp3XY-<platform>.whl` for
    CPython 3.11 to 3.14 on five platforms:
    `manylinux_2_17_x86_64.manylinux2014_x86_64`,
    `manylinux_2_17_aarch64.manylinux2014_aarch64`, `macosx_10_12_x86_64`,
    `macosx_11_0_arm64` and `win_amd64`;
  - `THIRD-PARTY-NOTICES`.

  That is 0.11.0's asset names (the five CLI binaries on GitHub, the wheels
  and sdist on PyPI) plus the CPython 3.14 wheels and `THIRD-PARTY-NOTICES`.
- `release-notes`: `notes.md`. Issue references such as `#1134` link to the
  GitHub issue of that number, which is the right one since the issues moved
  to GitHub (#1472). GitHub refuses bodies over 125,000 characters, so a
  longer section is cut at 120,000 with a link to the full `CHANGELOG.md`,
  closing any code block the cut leaves open.
- `notices`: `THIRD-PARTY-NOTICES`, which the sdist and wheel builds put in.
- `crates`, `sdist`, `wheels-<platform>` and `cli-<platform>`: each build
  job's output.

The repository keeps a run's artifacts for 90 days.

The Linux wheels and binaries need glibc 2.17 or newer, which covers
RHEL/CentOS 7, Debian 8, Ubuntu 14.04 and later: they are built on glibc 2.17
itself. The CLI links libpcap statically. Debian and Ubuntu name the shared
library `libpcap.so.0.8` and RHEL `libpcap.so.1`, so no single dynamically
linked binary could run on both.

### Builds

The pins the builds read beyond `rust-toolchain.toml` are in
[`.github/ci-pins.env`](../.github/ci-pins.env): maturin's version, the
manylinux2014 images' digests, rustup-init's version and digests, and
libpcap's version and digest. To move to a newer image, take a dated tag's
`manifest_digest` for each architecture from
`https://quay.io/api/v1/repository/pypa/manylinux2014_<arch>/tag/?specificTag=<tag>`;
the PR's dry run then builds and tests with it.

**Linux** ([`build_linux.sh`](../scripts/release/build_linux.sh)). On each
architecture's own runner, the script runs itself in the
`quay.io/pypa/manylinux2014_<arch>` image, pinned by digest, with the checkout
mounted. In the image it:

- installs the toolchain that `rust-toolchain.toml` pins, through a
  rustup-init checked against its pinned SHA-256;
- builds libpcap from the pinned tarball, checked against its SHA-256
  ([`libpcap.sh`](../scripts/release/libpcap.sh)), as a static,
  position-independent archive (the CLI is a position-independent
  executable). flex and bison, from the image's package manager, only
  generate its filter parser. The pcap crate links `-lpcap`, and with only
  `libpcap.a` in `LIBPCAP_LIBDIR` the linker takes the archive. `LIBPCAP_VER`
  tells the crate's build script the version, which it would otherwise load a
  shared libpcap to ask;
- builds the wheels with the pinned maturin (see below):
  `--compatibility manylinux2014` tags them `manylinux_2_17`, and
  `--auditwheel check` fails the build on a symbol or library outside that
  policy instead of copying a library into the wheel;
- builds the CLI with `--features sc-tls,pcap`.

AWS-LC (`aws-lc-sys`, for BACnet/SC) builds with the image's GCC 10 through
its default builder, which needs no CMake. Its build checks the compiler for
GCC's `memcmp` bug, which GCC 10.2 doesn't have.

**macOS and Windows** ([`build_native.sh`](../scripts/release/build_native.sh)).
The job installs the pinned toolchain and the four CPythons, and the script
builds the wheels with the pinned maturin, in a venv, then the CLI with
`--features sc-tls`.

Both scripts install maturin with `pip install --require-hashes --only-binary
:all: -r` [`maturin-requirements.txt`](../scripts/release/maturin-requirements.txt),
which names its version and the sha256 of each wheel the five build hosts can
pick (manylinux x86_64 and aarch64, macOS x86_64 and universal2, Windows
x86_64), from `https://pypi.org/pypi/maturin/<version>/json`.
`test_maturin_requirements.py` fails if that version differs from
`MATURIN_VERSION` in `.github/ci-pins.env`; bump them together.

- **Minimum macOS.** 10.12 on x86_64 and 11.0 on arm64, as in 0.11.0's wheel
  tags (`macosx_10_12_x86_64`, `macosx_11_0_arm64`) and Rust's defaults.
  `MACOSX_DEPLOYMENT_TARGET` sets it for Rust and the C code, and maturin
  takes the wheel tag from it. The x86_64 binaries carry
  `LC_VERSION_MIN_MACOSX` 10.12 and the arm64 ones `LC_BUILD_VERSION` with
  `minos 11.0`; the artifact check compares each with its tag.
- **Frameworks.** The CLI links no framework: BACnet/SC runs its own TLS
  handshake against its configured trust anchors and never uses the system's
  root certificates. The extension module links IOKit and CoreFoundation,
  for `serialport`'s port listing (MS/TP). Apple's linker binds their symbols
  to the frameworks; only Python's C API is left to a flat lookup at load
  time, since maturin links extension modules with `-undefined
  dynamic_lookup`. An arm64 file must carry a code signature
  (`LC_CODE_SIGNATURE`), which macOS requires on Apple Silicon; Apple's
  linker signs ad hoc.
- **Windows C runtime.** The CLI links it statically
  (`-C target-feature=+crt-static`), so it imports only Windows system DLLs
  and needs no Visual C++ Redistributable, which 0.11.0's did
  (`VCRUNTIME140.dll`). The wheels link it dynamically, like other extension
  modules: Python for Windows ships `VCRUNTIME140.dll`, and the Universal CRT
  (`api-ms-win-crt-*`) is part of Windows 10 and later. The artifact check
  enforces both.
- **Windows linking.** Both link with `-DEBUG:NONE` and `-Brepro` (link.exe's
  `/DEBUG:NONE` and `/Brepro`, spelled with `-` so that Git Bash doesn't take
  them for paths and convert them): the release ships no PDB, whose path and
  build ID change with every build, and `-Brepro` puts a hash of the output
  where the timestamps go. PyO3 links
  each extension module to its `pythonXY.dll` with raw-dylib, so no import
  library is needed; the artifact check makes sure each `.pyd` imports its
  own Python's DLL and no other. AWS-LC assembles its x86_64 assembly with the
  runner image's NASM.

`SOURCE_DATE_EPOCH`, the commit time, pins the sdist's and the wheels'
timestamps.

### Third-party notices

`scripts/release/third_party_notices.py` writes `THIRD-PARTY-NOTICES`: Rusty
BACnet's own licence, then every third-party component in the release
binaries with the licence files it ships, identical texts printed once.

- The crates come from `cargo tree --locked --offline -e normal,no-proc-macro`
  for the CLI (`-p bacnet-cli --features sc-tls,pcap` on Linux, `--features
  sc-tls` on macOS and Windows) and the Python extension (`-p rusty-bacnet`) on
  each of the five release targets, so build scripts, proc-macros,
  dev-dependencies and crates for other platforms, which no release binary
  contains, are left out. Platform crates such as `windows-sys` and
  `io-kit-sys` are in because a release binary contains them. The licence
  files are the ones at each crate's root, plus three for the C library that
  `aws-lc-sys` bundles: `aws-lc/LICENSE`, fiat-crypto's
  `aws-lc/third_party/fiat/LICENSE` (MIT), and the licence comment of
  jitterentropy's `jitterentropy.h`, which is built on Linux and Windows and
  whose BSD-3-Clause terms AWS-LC elects (the crate doesn't ship
  jitterentropy's `LICENSE`).
- Every component's row gives where its source is: a crate's crates.io page
  for that version (`https://crates.io/crates/{name}/{version}`), or its
  repository if it isn't from crates.io; libpcap's release tarball on
  tcpdump.org. MPL-2.0 needs this for `serialport`, which is in the wheels.
- Generation fails if a crate ships no licence file while its licence
  expression has any identifier other than `0BSD`, `BSL-1.0`, `CC0-1.0`,
  `MIT-0`, `Unlicense` and `WTFPL`, whose terms don't ask for the notice in a
  binary (so MIT, BSD-*, ISC, Apache-2.0, MPL-2.0 and unknown ones all count),
  unless `ALLOW_NO_LICENSE_FILE` in the script names it with the reason. The
  list is empty: every such crate ships a licence file. One crate ships none
  and is listed at the end with its reason: `clipboard-win` (BSL-1.0, in the
  Windows CLI through rustyline), whose licence exempts machine-executable
  object code.
- libpcap's licence and version come from the pinned tarball, which Validate
  fetches with `libpcap.sh`, as the Linux builds do.
- The file depends only on `Cargo.lock`, the crate sources and libpcap, so a
  rebuild writes the same file.

It's attached to each release, and `pyproject.toml`'s `license-files` puts it
in each wheel's `.dist-info/licenses/` and in the sdist; the artifact check
checks both. Local builds have no such file, and maturin skips it.

cargo-audit and cargo-deny don't cover libpcap, so its advisories need
tracking by hand: watch the [tcpdump/libpcap
releases](https://www.tcpdump.org/) and their security fixes, and bump
`LIBPCAP_VERSION` and `LIBPCAP_SHA256` in `.github/ci-pins.env` together.

### Re-running a partial release

Every publish job is safe to run again:

- **GitHub draft** resumes the tag's draft and leaves it holding exactly this
  run's files; on a published release it only checks.
- **crates.io**: `publish_crates.sh` publishes only the crate versions that
  aren't on crates.io yet.
- **PyPI trusted publishing** only mints and discards a token, so it can run
  any number of times.
- **PyPI** uploads without `skip-existing`. PyPI takes a file it already has
  with the same bytes as a no-op, and refuses a file of the same name with
  other bytes, so a re-run finishes a partial upload, and a rebuilt wheel that
  differs from the one on PyPI stops the release there.
- **GitHub release** publishes the staged draft, or only checks a release that
  is already published.

To finish a release after a failure, for example a network error, use
**"Re-run failed jobs"** on the tag's run. GitHub keeps the run's artifacts
and the outputs of the jobs that passed, so nothing is rebuilt: the jobs that
failed, and the ones after them, run again with the same files, and the
publish jobs pick up where they stopped. The CI gate runs again only if it
failed. The artifacts expire after 90 days.

"Re-run all jobs", or a `dry_run=false` dispatch on the tag, rebuilds every
artifact. Hosted runner images change every week or so, so a rebuild can give
other bytes than the first build. Before anything reached PyPI that is
harmless: the draft then takes the rebuilt files. Once PyPI has some of the
files, it refuses rebuilt ones that differ, and the release stops there with
the GitHub release still a draft. Finishing it then needs a new version.

### Secrets and environment

The release uses no repository secret. Each job's `GITHUB_TOKEN` has only the
permissions it declares (the workflow's default is none):

| Job | Token permissions | Also |
| --- | --- | --- |
| Validate, Crates and sdist, Build, Check the artifacts, Smoke test, Publish plan | `contents: read` | |
| CI gate | `actions: read`, `checks: read`, `contents: read` | |
| GitHub draft, GitHub release | `contents: write` | |
| Publish to crates.io | `contents: read` | the `release` environment's `CARGO_REGISTRY_TOKEN` |
| PyPI trusted publishing, Publish to PyPI | `id-token: write` only | the `release` environment, for trusted publishing |

- **The `release` environment.** Only tags matching `v*` may deploy to it (a
  custom deployment policy since 2026-10-04; before, only protected branches
  could). It holds `CARGO_REGISTRY_TOKEN`. Only the two jobs above deploy to
  it, so a dry run, whatever started it, gets no secret.
- **`CARGO_REGISTRY_TOKEN`**: a crates.io token that can publish new crates
  and update existing ones. 0.12.0 is the first release of `bacnet-endpoint`
  and `bacnet-cli`, which a token scoped to existing crates couldn't publish.
  crates.io trusted publishing may replace it later.
- **PyPI trusted publishing.** PyPI accepts the PyPI job's OIDC token for
  `rusty-bacnet` when the project's trusted publisher names owner
  `jscott3201`, repository `rusty-bacnet`, workflow `release.yml` and
  environment `release`. No PyPI token is stored anywhere. 0.11.0 was
  published from `ci.yml` (environment `release`), so PyPI's publisher still
  names `ci.yml`, whose release jobs moved out in #943. Before the first
  release, the owner adds the `release.yml` publisher on pypi.org and removes
  the `ci.yml` one (step 0 of [To release](#trigger-and-dry-run)). The PyPI
  trusted publishing job checks this before crates.io: it requests the job's
  OIDC token for PyPI's audience (`https://pypi.org/_/oidc/audience`),
  exchanges it at `https://pypi.org/_/oidc/mint-token`, masks the minted
  token with `::add-mask::` at once, never prints it and discards it (it
  expires after 15 minutes). If PyPI refuses, the job prints PyPI's reason and
  fails, and nothing is published.
- **Fork PRs** run the dry run with a read-only token and no secret, as GitHub
  gives every fork's `pull_request` run.
- The actions are pinned to full commit SHAs, as the repository requires, and
  no step expands an input or event field into its script: they reach the
  scripts as environment variables.

### macOS and Windows

The macOS and Windows artifacts are built on GitHub's macOS and Windows
runners and smoke-tested there before a release publishes anything. These
checks do not establish hardware qualification, support for macOS or Windows
versions older than the runners', or release readiness.
