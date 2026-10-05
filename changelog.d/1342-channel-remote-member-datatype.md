---
section: Changed
---
- **Wire, Breaking (Rust API):** A Channel reads a remote member's datatype and
  coerces its value to it, so a remote Binary Output takes REAL 1.0 as ACTIVE;
  an unanswered read fails the member unsent, a refused one sends the value as
  written. `CovAckResult` gains `Data` (#1342).
