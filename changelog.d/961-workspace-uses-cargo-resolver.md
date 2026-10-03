---
section: Changed
commit: 6d866b683f92c23fd06a0ed0d2ab4e5e17f4ccc8
---
- The workspace uses Cargo's `resolver = "3"`, so lock file updates prefer
  dependency versions that support the MSRV (#961).
