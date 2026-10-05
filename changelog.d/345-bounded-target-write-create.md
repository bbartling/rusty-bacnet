---
section: Changed
---
- **Rust and Python API:** a server can run 1 to 64 target Audit Reporters
  that send bounded notifications for inbound writes, list edits, file writes
  and object creation and deletion, plus summaries of dropped records; the
  lowest instance is elected and all share one admission budget (#345, #782).
