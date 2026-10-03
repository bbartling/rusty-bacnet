---
section: Changed
---
- **Rust and Python API:** WritePropertyMultiple request encoding returns
  `Result` and validates every write first, refusing empty lists, special
  property selectors and invalid priorities (#793).
