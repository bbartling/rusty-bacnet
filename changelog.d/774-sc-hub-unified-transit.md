---
section: Changed
---
- **SC Hub unified transit budget (Refs #774, #476):** replace the unfrozen
  unicast-only Rust setting/validator with `with_relay_send_budget`,
  `relay_send_budget` and `validate_relay_send_budget`, and the Python keyword
  with `relay_send_budget_ms`. No aliases remain. Default five-second attempts
  now share one configured budget across NPDU/opaque unicast, each concurrent
  broadcast recipient and forwarded BVLC-Result, including sink acquisition.
  Timeout does not retire, retry or fabricate a response. Probe/control/cleanup/
  graceful policies remain distinct; unicast outcome counters keep their scope.
  Real TLS tests cover concurrent fanout, replacement, later delivery and a
  concurrent peer-close wave recovering capacity before joined shutdown.
