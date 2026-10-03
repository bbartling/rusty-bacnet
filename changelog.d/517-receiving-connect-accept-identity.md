---
section: Changed
---
- **Receiving Connect-Accept identity compatibility break (Refs #517):** after
  TLS/WebSocket setup, initiating nodes silently discard an all-zero peer UUID.
  Annex AB.2 prohibits responses to response messages, so no NAK is sent. Invalid
  Accepts cannot publish Connected, peer identity or limits, reset the absolute
  connect wait, or reseed the local VMAC. A later valid Accept can complete the
  same handshake; nil-only traffic expires the original wait. This local nonzero
  policy reaches native Python SC client/server startup without API changes.
  Nonzero bits stay opaque; generic nil codec syntax and existing malformed
  Accept silence remain. No persistence, certificate binding, full Annex AB or
  direct-connection claim; #517 remained open at slice time.
