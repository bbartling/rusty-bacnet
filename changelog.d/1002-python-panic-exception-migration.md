---
section: Migration notes
---
- **Python panics (#1002):** a Rust panic in an async method now raises PyO3's
  `PanicException` instead of `pyo3_async_runtimes.RustPanic`. It derives from
  `BaseException`, so `except Exception` no longer catches it.
