---
section: Changed
---
- The server bounds request admission with configurable global and per-peer
  quotas, keeps a reserve for DCC ENABLE, and joins its request work on stop;
  see the
  [acceptance matrix](docs/request-admission.md#bounded-acceptance-and-evidence)
  (#521).
