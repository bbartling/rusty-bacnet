---
section: Changed
---
- Test-only: the endpoint Device-write tests bind port 0 and read the real
  address back, the benchmarks hub-restart test retries on a lost bind instead
  of probing the old address, and the BBMD several-own-rows test reruns on a
  lost port. The macOS limit of the BBMD probe retry is documented (#1068).
