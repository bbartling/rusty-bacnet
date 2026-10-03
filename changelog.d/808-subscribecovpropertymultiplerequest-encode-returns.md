---
section: Fixed
---
- `SubscribeCOVPropertyMultipleRequest::encode` now returns `Result` and validates
  the whole request before appending bytes (#808). The `try_encode`/panicking
  encoder split is removed. Python validates every nested specification and timing
  synchronously before returning an awaitable or accessing the client; an invalid
  later entry cannot dispatch a valid prefix. Existing finite and cancellation
  wire shapes remain available, without expanding server context behavior.
