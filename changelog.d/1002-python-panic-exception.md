---
section: Fixed
---
- **Breaking Python panic exception:** a Python process that used the bindings
  no longer segfaults at exit while a Tokio thread completes an awaited
  future, such as `stop()` (#1002). Completing a future calls
  `loop.call_soon_threadsafe`, which releases the GIL after queueing the
  callback; the main thread could finish the program in that window, and
  CPython 3.12 and 3.13 end a thread that takes the GIL back during
  finalization, unwinding it through Rust frames that then dropped Python
  objects without the GIL (51 of 800 fresh processes that exit right after
  `await server.stop()` on the CI image under load, and none of 800 with this
  fix). The bindings now bridge Tokio futures to asyncio themselves
  (`py_async`) instead of through `pyo3-async-runtimes`, which is no longer a
  dependency. Binding threads touch Python only through an exit gate, and an
  `atexit` hook, which runs before finalization starts, closes it and waits
  for them with the GIL released. A future requested after that hook raises
  `RuntimeError` instead of never completing. A Rust panic in an async method
  now raises PyO3's `PanicException`, as a panic in a synchronous method does,
  instead of `pyo3_async_runtimes.RustPanic`; `PanicException` derives from
  `BaseException`, so `except Exception` no longer catches it.
