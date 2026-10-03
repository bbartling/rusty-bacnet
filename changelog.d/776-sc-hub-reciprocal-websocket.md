---
section: Changed
---
- **SC Hub reciprocal WebSocket Close (Refs #776):** registered, pre-Connect
  and graceful Disconnect-Ack-wait peers receive Tungstenite's queued Close
  reply through the existing bounded lease cleanup. The Hub preserves the peer's
  allowed code/reason, removes only the matching registration and reclaims its
  active slot. A peer closing before Disconnect-Ack still produces a forced
  shutdown outcome; forceful abort may forgo the reply. No TLS `close_notify`
  or broader Annex AB conformance claim is added.
