---
section: Fixed
---
- Ordinary SubscribeCOV typed request encoding now returns `Result` and rejects
  a lifetime without confirmed-notification mode before appending bytes (#805).
  The server rejects that malformed shape before lookup, expiry cleanup or state
  changes. Public Rust/Python optional lifetimes retain None/zero indefinite
  subscriptions and explicit cancellation.
