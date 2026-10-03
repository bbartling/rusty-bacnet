---
section: Fixed
---
- **Python API:** the remaining 104 native methods that return futures are
  typed `def -> Awaitable[T]` instead of as coroutines (#858).
