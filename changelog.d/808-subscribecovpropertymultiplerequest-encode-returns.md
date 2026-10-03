---
section: Fixed
---
- **Rust and Python API:** `SubscribeCOVPropertyMultipleRequest::encode`
  returns `Result` and validates the whole request first, and Python validates
  every entry before it sends anything (#808).
