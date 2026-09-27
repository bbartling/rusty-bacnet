# GitLab Linux CI

[`.gitlab-ci.yml`](../.gitlab-ci.yml) defines validation on GitLab.com-hosted
Linux amd64 runners for the
[GitLab project](https://gitlab.com/justinscott-group/rusty-bacnet).
It preserves the existing Linux gate commands and workspace lint policy.
The Debian Bookworm container userland differs from GitHub's Ubuntu runners.
Configuration and image metadata are not evidence that a hosted run passed;
use the pipeline and job results for the exact commit being reviewed.

## Pipeline and job scope

| Event | Lean gates | Linux heavy gates | Website validation |
| --- | --- | --- | --- |
| Merge request targeting `dev` | Yes | No | When inputs change |
| Merge request targeting `main` | Yes | Yes | When inputs change |
| Push to `main` | Yes | Yes | When inputs change |
| Other branch push, tag, schedule, or manual pipeline | No pipeline | No pipeline | No pipeline |

Feature-branch pushes do not create a second branch pipeline alongside the
merge-request pipeline. Explicit job rules include all five lean gates in MR
pipelines. New commits can cancel superseded interruptible jobs.

The five lean jobs run Rustfmt, Clippy, the strict 700-LOC file-size cap, the
baseline secret scan, and the workspace Linux tests. Rust is pinned to 1.97.1.
Clippy retains `--workspace --exclude rusty-bacnet --all-targets --locked` and
the workspace's per-rule severity; CI does not promote all warnings to errors.
The Linux test job retains `--workspace --exclude rusty-bacnet --locked` with
`bacnet-types/serde,bacnet-transport/ipv6,bacnet-transport/sc-tls,bacnet-transport/serial,bacnet-transport/ethernet`.
The secret-scan job also tests its redacted diagnostics with synthetic inputs.
Diagnostics identify matches by a stable opaque path ID and line number;
filenames can themselves contain credentials, so neither paths nor matching
text are printed. To compare a suspected repository-relative path locally,
compute its ID with `printf '%s' "$path" | git hash-object --stdin`.
The shared gate scripts stay in `.github/scripts/`; both CI systems invoke the
same implementations.

Main-target MRs and main pushes additionally run the existing MSRV 1.93 script,
`cargo audit --color always`, and `cargo deny --all-features check`. The deny
features match the default of the existing GitHub `cargo-deny-action@v2`.
The MSRV script continues to derive publishable crates and feature coverage;
this migration does not expand its optional-feature contract. Cargo Audit
0.22.2 and Cargo Deny 0.20.2 are installed with their published lockfiles.
Advisory databases remain live inputs, so results can change without a source
change.

Website validation runs when `website/**`, `.gitlab-ci.yml`, or the existing
GitHub docs workflow changes. It uses Node 24, `npm ci`, Chromium installation
with Linux dependencies, and `npm run verify`. Failed runs retain existing
Playwright reports and test results for seven days. No site is published.

## Runners and images

Clippy, Linux tests, and MSRV request `saas-linux-medium-amd64` (4 vCPU, 16 GB).
These compilation jobs start with `CARGO_BUILD_JOBS=1`. Other jobs request
`saas-linux-small-amd64` (2 vCPU, 8 GB); audit/deny installs also limit build
parallelism. Native compilation jobs have a 60-minute timeout, audit/deny
30 minutes, and lighter checks and docs 20 minutes. Hosted availability,
project quotas, and actual memory usage require live job evidence.

Official Docker Hub image index digests were checked against public tag
metadata on 2026-09-27 and pinned in the YAML. Each index has a Linux amd64
manifest. No image was built or published by this change.

| Official image | Pinned index digest |
| --- | --- |
| `rust:1.97.1-bookworm` | `sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97` |
| `rust:1.93-bookworm` | `sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31` |
| `node:24-bookworm` | `sha256:64af3819f9275802414d7cdc38c27e9d82bd564dec4d4da87d008255d36c63b4` |

Rustfmt/Clippy components and native system packages are installed explicitly.
The MSRV job selects the 1.93 toolchain independently of `rust-toolchain.toml`
and installs Python for metadata processing. There is initially no shared
build cache. Jobs need network access for package and advisory downloads, but
no custom secret, publishing token, deployment environment, or service is
configured. GitLab's normal checkout/job authentication still applies.

Primary references: [hosted Linux runners](https://docs.gitlab.com/ci/runners/hosted_runners/linux/),
[pipeline workflow rules](https://docs.gitlab.com/ci/yaml/workflow/),
[Rust 1.97.1 image metadata](https://hub.docker.com/v2/repositories/library/rust/tags/1.97.1-bookworm),
[Rust 1.93 image metadata](https://hub.docker.com/v2/repositories/library/rust/tags/1.93-bookworm),
[Node 24 image metadata](https://hub.docker.com/v2/repositories/library/node/tags/24-bookworm),
and [cargo-deny action defaults](https://github.com/EmbarkStudios/cargo-deny-action/blob/v2/action.yml).

## Remaining migration scope

The existing [GitHub CI](../.github/workflows/ci.yml) and
[docs publication workflow](../.github/workflows/docs-pages.yml) remain in the
repository. This Linux pipeline does not replace their macOS/Windows runtime
tests, tag/version/changelog release validation, Linux/macOS/Windows wheel and
CLI builds, source distributions, crates.io/PyPI publication, GitHub releases,
or reviewed documentation publication. Those paths require separate migration
and qualification. Installed Python-extension tests also remain separate.
A green GitLab Linux pipeline does not establish cross-platform support,
hardware qualification, installed Python behavior, or release readiness.
