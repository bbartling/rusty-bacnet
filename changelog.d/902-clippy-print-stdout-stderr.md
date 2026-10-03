---
section: Changed
---
- `clippy::print_stdout` and `clippy::print_stderr` are now `deny` across the
  workspace. The CLI, benchmark binaries, examples and tests allow printing, each
  with a reason; library crates report through `tracing` (#902).
