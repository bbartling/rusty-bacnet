---
section: Changed
---
- Pre-1.0 AddListElement/RemoveListElement request encoding now returns `Result`
  and rejects index zero, empty elements and malformed tag framing transactionally.
  Rust clients reject before admission; both Python methods validate synchronously.
  Empty-valued/context/constructed/vendor elements remain opaque; inbound target
  validation and malformed-list atomicity are unchanged (#798).
