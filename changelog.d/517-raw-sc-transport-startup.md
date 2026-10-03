---
section: Changed
---
- **Raw SC transport startup compatibility break (Refs #517):** the two-argument
  `ScTransport::new(ws, vmac)` retains its unstarted zero UUID placeholder, but
  `start()` now requires `.with_device_uuid([u8; 16])` with a nonzero value and
  rejects all-zero/all-ff local VMACs. Reconnect and heartbeat errors retain
  precedence. Identity failure leaves sockets/state untouched before transport-owned
  I/O; correct the UUID with the existing setter and retry on the same owned
  WebSocket. This cannot undo caller-owned dials or promise generic endpoint
  rollback/all-field repair. No constructor argument, VMAC setter, UUID generation,
  storage backend, version/variant or general VMAC shape policy is added.
  Caller-owned predeployment generation and durable lifetime reuse remain required;
  this is startup enforcement, not lifetime immutability against application
  mutation through public `connection()`. Pure codec/manual WebSocket use, later
  handshake validation, peer admission and internal reconnect/reseed behavior are
  unchanged. Raw runtime fixtures and mTLS benchmarks supply explicit test identities,
  distinct for coexisting devices. #517 remained open at slice time; no full-profile promotion.
