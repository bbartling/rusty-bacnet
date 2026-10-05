---
section: Changed
---
- The samples in `examples/rust/samples` are workspace members outside the
  default build. They share the workspace's `Cargo.lock` instead of keeping
  their own, which could go stale, and CI lints and tests them with the rest
  of the workspace (#1406, #1450).
