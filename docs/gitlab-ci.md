# GitLab Linux CI and local merge evidence

[`.gitlab-ci.yml`](../.gitlab-ci.yml) runs one full-feature Linux test job on
GitLab.com-hosted Linux amd64 runners for the
[GitLab project](https://gitlab.com/justinscott-group/rusty-bacnet) (project access
required). Checks practical on the development machine run locally and remain
required merge evidence. A green hosted pipeline alone is insufficient to merge.

## Pipeline scope

| Event | Hosted jobs | Required local evidence |
| --- | --- | --- |
| Merge request targeting `dev` | Linux tests | Routine checks; website checks when applicable |
| Merge request targeting `main` | Linux tests | Routine checks, MSRV/audit/deny; website checks when applicable |
| Branch push, including `dev`/`main` | No pipeline | Changes must enter protected targets through a reviewed MR |
| Other MR target, tag, schedule, or manual pipeline | No pipeline | No merge or release qualification implied |

Feature pushes and post-merge pushes do not create redundant branch pipelines.
Explicit job rules include the Linux test job in MR pipelines; new commits can
cancel superseded interruptible jobs. Both `dev` and `main` must remain protected
against direct pushes in GitLab project settings. Verify those settings
separately: YAML does not enforce branch protection. Main-target local checks
must pass before merging to `main`; there is no post-merge pipeline to perform
them afterward.

## Required local checks

Run these commands from the repository root on the revision being reviewed.
Use Rust 1.97.1 from `rust-toolchain.toml`, with Rustfmt and Clippy installed:

```bash
rustup component add rustfmt clippy
cargo fmt --all --check
cargo clippy --workspace --exclude rusty-bacnet --all-targets --locked
bash .github/scripts/check-file-size.sh
bash .github/scripts/test-check-no-secrets.sh
bash .github/scripts/check-no-secrets.sh
```

Keep the workspace's per-rule lint severity; do not add `RUSTFLAGS=-Dwarnings`.
Run the file-size gate in its default strict mode, without
`CHECK_FILE_SIZE_WARN=1`. The scanner regression and live tracked-file scan are
both required. Diagnostics use stable opaque path IDs and line numbers because
filenames can contain credentials too; neither paths nor matching text are
printed. Compare a suspected repository-relative path locally with
`printf '%s' "$path" | git hash-object --stdin`.

For every MR targeting `main`, additionally run:

```bash
rustup toolchain install 1.93 --profile minimal
RUSTUP_TOOLCHAIN=1.93 bash .github/scripts/check-msrv.sh --linux-native
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --color always
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --all-features check
```

The MSRV command is required **local Linux GNU evidence** for `main` targets.
Provide an installed native Rust/Cargo 1.93 toolchain, Python 3, a C toolchain,
`pkg-config`, `libpcap-dev` (Debian package name), `file`, and `ldd`, plus `cmake`
and `perl` for the selected TLS provider. The compiler's GNU host triple must
match the Linux host architecture reported by `uname -m`. macOS/Windows users
must run this check in a separately provided Linux environment. The script
does not install tools, skip unavailable features, start Docker or use hardware.
The qualified serial/GPIO build needs neither `libudev-dev` nor `libgpiod-dev`.

The script derives metadata-eligible packages (currently 11); eligibility is
not proof of registry publication, which remains separate work in #195.
`--linux-native` runs that baseline with its SC/IPv6 features, then separate
locked transport checks for `ethernet`, `serial` and `serial-gpio`, and an actual
locked `bacnet-cli --bin bacnet --features pcap` build. It resolves the executable
from the successful Cargo JSON artifact, honors `CARGO_TARGET_DIR`, and requires
an ELF executable with resolved dynamic `libpcap.so` and no `ldd` `not found`.
Conflicting compiler/cross-target environment settings and active environment
compiler wrappers fail; configured compiler/wrapper/target defaults are replaced
by the verified compiler, disabled wrappers and an explicit native target.

The no-argument `RUSTUP_TOOLCHAIN=1.93 bash .github/scripts/check-msrv.sh` remains
the baseline used by the retained GitHub invocation; it is not the complete
local Linux-native gate. The explicit toolchain selection overrides the development
pin for these commands only. Script guard/parser regressions run with
`python3 .github/scripts/test-check-msrv.py`; shims in those tests do not establish
actual Linux compilation or dynamic linkage. Reuse already
installed Cargo Audit 0.22.2 and Cargo Deny 0.20.2 after verifying their versions;
the install commands specify exact versions and published lockfiles. Deny's
`--all-features` preserves the existing GitHub action's default.

For MRs changing `website/**`, `.gitlab-ci.yml`, or
`.github/workflows/docs-pages.yml`, use Node 24 and run:

```bash
(
  cd website
  export DOCS_TEST_PORT=46329
  npm ci
  npx playwright install --with-deps chromium
  npm run verify
)
```

These commands preserve the existing website checks, unit tests, production
build, and Chromium tests. Local failures leave `website/playwright-report/`
and `website/test-results/`; retain relevant failure evidence with the review
record. There is no GitLab docs job or automatic artifact upload. No site is
published by these commands.

## Merge evidence and reuse

Before merging, the root must verify both a successful hosted Linux test job
for the exact reviewed MR head and passing recorded local checks applicable
above, alongside the existing review and merge-authorization requirements.
Record the source revision, command, result, tool versions, operating system,
and log or artifact location in the MR or linked review record. Identify each
check as local or hosted. An unrun, failed, or inapplicable check must not be
reported as passed.

Successful local evidence can be reused when its relevant inputs are unchanged.
Record the original tested revision and result, the new reviewed revision,
and why the intervening diff does not affect that check's source, dependencies,
features, scripts/configuration, or execution environment. A branch name or an
old green pipeline alone is not sufficient provenance. Re-run affected checks;
do not repeat unrelated successful work merely because the MR head changed.
Audit and deny consult mutable advisory databases: unchanged source alone
does not establish that their previous results remain current. Refresh those
checks for the main-target merge decision and record the database freshness.
Required checks that cannot run locally remain unresolved until equivalent
evidence is obtained; moving them out of hosted CI does not waive them.

## Hosted runner and image

The sole job uses `saas-linux-small-amd64` (2 vCPU, 8 GB memory, 30 GB storage),
`CARGO_BUILD_JOBS=1`, and a 60-minute timeout. The complete suite has passed on
this runner: the latest [!892 pipeline](https://gitlab.com/justinscott-group/rusty-bacnet/-/pipelines/2887870969)
and [Linux job](https://gitlab.com/justinscott-group/rusty-bacnet/-/jobs/16768305398)
(project access required) completed in 637.6 seconds with about 11 GiB free;
earlier observed passes took 666 and 739.6 seconds. These runs establish observed
fit, not a controlled compute-cost comparison or a guarantee of future headroom.
Record the runner, duration, and any OOM or resource failure for later runs.
The job prints `df -h` before setup and in `after_script` for disk-headroom
inspection; abrupt termination may prevent the final diagnostic. If memory or
disk pressure or a material regression occurs, report that evidence for a
bounded repair or fallback; do not suppress tests or change feature coverage
or add further build-profile overrides to manufacture a pass.

This job alone sets `CARGO_PROFILE_TEST_DEBUG=0` to omit native test debug
symbols and reduce code-generation, linking, and disk costs. Optimization level,
debug assertions, overflow checks, and test selection retain their existing
defaults; no `RUSTFLAGS` or other profile override is introduced. The setting
also changes the `DEBUG` environment observed by build scripts, so these builds
are not claimed to be binary-equivalent to previous builds with full symbols.
The observed passes establish fit with this setting; controlled savings remain
unmeasured. The complete runtime suite and doctests must still pass for each head.

The exact locked command remains:

```bash
cargo test --workspace --exclude rusty-bacnet --locked --features bacnet-types/serde,bacnet-transport/ipv6,bacnet-transport/sc-tls,bacnet-transport/serial,bacnet-transport/ethernet
```

The pinned official image is `rust:1.97.1-bookworm` at index digest
`sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97`,
verified against public Docker Hub metadata on 2026-09-27. Its Linux amd64
manifest supplies a Debian Bookworm userland, which differs from GitHub's
Ubuntu runners. The job explicitly installs `pkg-config`, `libudev-dev`,
`cmake`, and `perl`. No cache, custom credential, deployment environment, or
service is configured. GitLab's normal checkout/job authentication applies.

Primary references: [hosted Linux runners](https://docs.gitlab.com/ci/runners/hosted_runners/linux/),
[pipeline workflow rules](https://docs.gitlab.com/ci/yaml/workflow/),
[Rust image metadata](https://hub.docker.com/v2/repositories/library/rust/tags/1.97.1-bookworm),
[cargo-deny action defaults](https://github.com/EmbarkStudios/cargo-deny-action/blob/v2/action.yml),
[Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html),
and [Cargo build performance](https://doc.rust-lang.org/cargo/guide/build-performance.html).

## Remaining qualification scope

The existing [GitHub CI](../.github/workflows/ci.yml) and
[docs publication workflow](../.github/workflows/docs-pages.yml) remain in the
repository. This Linux pipeline and the local checks above do not replace
macOS/Windows runtime tests, tag/version/changelog release validation,
Linux/macOS/Windows wheel and CLI builds, source distributions, crates.io/PyPI
publication, GitHub releases, or reviewed documentation publication. Those
paths require separate migration and qualification. Installed Python-extension
tests remain separate. These checks do not establish cross-platform support,
hardware qualification, installed Python behavior, or release readiness.
