---
section: Changed
---
- The workspace uses Cargo's `resolver = "3"`, so updating the lock file
  prefers dependency versions that support the declared MSRV (1.93). Feature
  resolution is unchanged, and the MSRV CI job still checks the lock file
  (#961).
