---
section: Changed
---
- **SC hub unicast progress (Refs #762):** bound each inline NPDU and addressed
  opaque relay attempt to five seconds, including destination sink acquisition.
  A blocked destination no longer holds the source reader indefinitely. Timeout
  alone neither retires the destination, retries the frame nor fabricates a
  Result; terminal-error retirement and heartbeat liveness remain unchanged.
  Cancellation cannot retract bytes already buffered by the WebSocket.
