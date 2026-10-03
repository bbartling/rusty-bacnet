---
section: Changed
---
- Bound server request admission with configurable global/logical-peer quotas,
  inclusive counters and deterministic overload handling, including the known
  counted-drop fallback when all eight owned Abort workers are busy. Explicit stop
  joins owned requests, Abort workers, known descendants and producers. DCC ENABLE
  has a strict recovery reserve and independent per-peer quota (default 16 ordinary
  plus 1 recovery in either arrival order). The owner-accepted bounded #521 scope
  is complete, not a general fairness, availability or full-conformance guarantee;
  see the [acceptance/evidence matrix](docs/request-admission.md#bounded-acceptance-and-evidence).
