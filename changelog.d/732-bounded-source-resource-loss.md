---
section: Changed
---
- **Bounded source resource-loss summaries (Refs #732, #345):** endpoint source
  READ records lost to audit-permit or shared confirmed-transaction exhaustion
  coalesce into one memory-only AUDITING_FAILURE batch. Both notification modes
  retain the earliest admitted record's timestamp and a saturating Unsigned
  count; local Device identity is used for both source and target. Actual
  requester releases wake pending confirmed summaries. Encoding/size, shutdown,
  transport/ACK and summary failures never increment the count or recurse.
  Source and target batches now retain an immutable Reporter configuration and
  discard incompatible counts on mutation, replacement or removal, including
  A-to-B-to-A changes. Stale deliveries cannot change newer configuration health.
  No ordinary-record queue, durable delivery or full Audit support is claimed.
  Internal pre-1.0 delivery tokens now carry configuration and failure authority;
  audit admission distinguishes exhaustion from closed ownership.
