---
section: Changed
---
- **Rust and Python API:** the endpoint client sends ReadRange through the
  shared request path and records one source Audit READ per attempt; ReadRange
  request encoding returns `Result` (#771, #345).
