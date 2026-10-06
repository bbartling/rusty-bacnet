---
section: Added
---
- **CLI:** `read-range` takes `--position`, `--sequence` or `--time` with
  `--count`, shows result flags, first sequence number and broken rules
  (`--strict` refuses), and pages a log with `--all`, printing what it read
  before an error; `--min-interval-ms` paces requests (#1532).
