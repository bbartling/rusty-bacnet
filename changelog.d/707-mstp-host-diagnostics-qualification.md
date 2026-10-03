---
section: Changed
---
- **MS/TP host diagnostics and qualification method (Refs #707, #502 / RB-26):**
  Rust `MstpTransport::diagnostics()` exposes a cloneable, redacted, saturating
  counts-only handle that remains readable after stop/drop. Counts distinguish
  direct and token-queued DNER, DER, ReplyPostponed, host timeout/decode/assembly,
  queue/delivery and serial-error events without changing wire behavior or timers.
  [Bench method](docs/mstp-qualification.md) and an unrun JSON result template
  separate host evidence from independent wire measurements. This is not a
  19200/9600 fix, hardware qualification, routing-profile expansion or issue closure.
