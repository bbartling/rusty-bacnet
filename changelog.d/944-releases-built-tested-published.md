---
section: Changed
---
- Releases are built, tested and published from Forgejo
  (`.forgejo/workflows/release.yml`), which keeps the heavy work on the
  project's fixed-cost runner VM, and each one is copied to GitHub Releases.
  A manual dispatch is a dry run that publishes nothing. The Linux runner
  cross-compiles every artifact: the Linux and macOS ones with zig, and the
  Windows ones for the MSVC target with cargo-xwin and the Microsoft CRT and
  Windows SDK in the CI image. That
  includes the macOS (x86_64, arm64) and Windows (x64) wheels and CLI binaries
  that 0.11.0 built on GitHub's runners, under the same names, with the same
  minimum macOS (10.12 on x86_64, 11.0 on arm64). The Windows CLI now links the
  C runtime statically, so it no longer needs the Visual C++ Redistributable.
  The release's artifact test checks every file's architecture and linked
  libraries, and the macOS files' minimum OS and code signatures, but it can
  only run the Linux ones (#944). Starting with the next release, `bacnet-cli`
  and `bacnet-endpoint` are published on crates.io; the Linux CLI binaries
  need glibc 2.17 instead of 2.39, so they
  run on RHEL/CentOS 7, Debian 8, Ubuntu 14.04 and later, and link libpcap
  statically; and each release has a `SHA256SUMS` file and a
  `THIRD-PARTY-NOTICES` file, which the wheels and the sdist also carry.
  CPython 3.14 wheels ship once the release pipeline publishes (#943).
  Before anything is published, GitHub-hosted runners now run the macOS
  (Apple Silicon and Intel) and Windows artifacts: each CPython 3.11 to 3.14
  wheel in a fresh virtual environment, with an import, the serial port
  listing and a loopback client/server round trip, and each CLI binary's
  `--version`, `--help` and quickstart read against a local server. The files
  reach GitHub on the release's GitHub draft, which the release copy later
  publishes unchanged; a failure or timeout stops the release, and a dry run
  smoke-tests a throwaway draft and deletes it. The old manual-only GitHub
  release workflow is gone (#951).
