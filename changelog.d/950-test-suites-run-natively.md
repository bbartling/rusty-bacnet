---
section: Changed
---
- The test suites also run natively on macOS (Apple Silicon) and Windows
  (x86_64, MSVC): a GitHub Actions workflow on the mirror runs the tests,
  doctests, clippy and rustdoc with every feature those platforms build, and
  the Python suite and PyO3 crate tests, for every pushed branch
  (`.github/workflows/native-tests.yml`). Linux CI, releases and publishing
  stay on Forgejo. A PR merges only when Forgejo CI and both native jobs are
  green on its head; `scripts/ci/local-macos.sh` is now optional. Text files
  now check out with LF line endings on every OS (`.gitattributes`), so
  Windows checkouts match the repository (#950).
