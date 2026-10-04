---
section: Fixed
---
- A server stopped mid-request, or a durable object dropped, while a write was
  staged now puts storage back to the served state, so a restart no longer
  serves a list no client saw (#1363). `stop()` waits for queued durable saves,
  warning while storage stalls.
