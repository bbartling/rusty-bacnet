---
section: Fixed
---
- Correct the remaining 43 Python unit-only native Future results to actual
  `None` (#865), matching their existing `Awaitable[None]` declarations. This
  covers client operations, server lifecycle and both local writes, hub
  lifecycle, and endpoint broadcasts. Meaningful data/tuple/self results,
  exception mapping and synchronous validation timing are unchanged. Empty
  tuples are no longer returned for these unit-only successes.
