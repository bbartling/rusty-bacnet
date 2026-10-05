---
section: Changed
---
- **Rust and Python API:** one SC hub relay send budget, five seconds unless
  configured, bounds every unicast, broadcast and forwarded-result relay, so a
  blocked destination no longer holds up the source's reader (#762, #774,
  #476).
