---
section: Fixed
---
- Correct the remaining 104 Python native Future-returning declarations to
  ordinary `def -> Awaitable[T]` (#858), preserving arguments and awaited values.
  Type checkers now reject coroutine-only consumers such as `create_task` for
  these calls while retaining `await`, `ensure_future`, async context managers
  and COV iteration. The three batch result contracts remain unchanged; native
  execution, eager validation, cancellation and cleanup behavior are unchanged.
