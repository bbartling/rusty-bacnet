---
section: Changed
---
- **Bounded target WRITE/CREATE/DELETE Audit Reporter (RB-21a/b/c/d/e/f/g, Refs #345):** Rust servers can
  select one locally configured Reporter and explicitly bound unicast Device
  recipient. Successful inbound WriteProperty and each committed WPM prefix
  element produce separate immediate-send notifications after authorization and
  commit, subject to Reporter-level Audit_Level, WRITE, and command-priority
  filters. RB-21b adds execution-error completion after the existing decode,
  semantic prechecks, and authorization boundary: WP emits at most one failure
  record with the actual mapped BACnet Error in Result; WPM preserves each
  committed-prefix success, emits one failed-element record, and stops. Successes
  still omit Result. Policy/authorization denials, undecoded or unattempted
  elements, unknown/timeout outcomes, disabled reporting, and sensor samples
  remain silent. Failure reporting uses the same filters and never changes the
  protocol response or rolls back writes.
  RB-21c adds optional, local-only `Monitored_Objects` configuration through
  `AuditReporterObject::set_monitored_objects`: omitted selection preserves
  catch-all behavior; an explicit empty/all-NULL array selects no ordinary targets;
  exact object and object-type selectors admit matching successes and execution
  failures without duplicate notifications. Enabled Reporter-target writes bypass
  selection. The optional read-only property, RP/RPM array indexing, Property_List,
  and runtime PICS reflect local presence; network WP/WPM cannot mutate it.
  RB-21d adds immediate target CreateObject/DeleteObject successes and authorized
  execution failures, preserving responses, initial-value rollback, and deletion
  COV cleanup. CREATE uses the final/candidate OID, including assigned instances;
  DELETE retains the removed OID. These configuration operations require their
  respective operation bits, ignore the priority filter, and use the existing
  object selection (Reporter targets bypass selection, not NONE or operation bits).
  Records omit property, priority, and values; initial values do not generate
  separate WRITE records. By-type failures before a representable OID is assigned
  omit it rather than inventing one; only catch-all/type selection can match.
  Deleting the selected Reporter remains permitted and reports the committed
  removal through the captured instance-owned delivery state; later operations
  are silent while that configured Reporter is absent. No createability or
  deletability expansion is included.
  RB-21e adds AddListElement/RemoveListElement successes and authorized execution
  failures as WRITE records after complete element/framed decoding. Records carry
  object/property/requested index, no priority, the raw requested delta as
  Target_Value and the known pre-mutation Current_Value (non-empty, structurally
  valid values up to 32 encoded octets only; no wrapping or truncation). Successful
  no-op removals still report once; duplicate additions and existing responses,
  mutation atomicity, framing, caps, and event behavior are unchanged. Non-Present_Value
  lists pass AUDIT_CONFIG; priority filtering does not apply.
  RB-21f adds inbound AtomicWriteFile successes and authorized execution failures
  as at most one immediate WRITE record per operation. Records carry the known
  target OID and omit property, priority, target/current values, and synthetic file
  fields. Success omits Result; failures carry the unchanged response-mapped Error.
  AUDIT_CONFIG and AUDIT_ALL admit file writes when WRITE is enabled; NONE and
  unmatched object selection suppress ordinary targets, and priority filtering
  is irrelevant. Admission follows the existing service decoder acceptance
  boundary, including tolerated trailing bytes; this is not decoder hardening.
  Decoder rejections, policy/authorization denials, configured stream/record
  payload/count budget Aborts, and unknown Timeout/Reject/Abort outcomes stay
  silent. Existing ACK positions, error precedence, access gates, storage
  atomicity and delivery ownership are unchanged. Inbound WriteGroup remains
  unsupported by design, so complete WRITE coverage is not claimed.
  RB-21g summarizes already-selected, execution-completed records dropped by the
  64-active delivery limit or confirmed coordinator exhaustion. When Audit_Level
  and the AUDITING_FAILURE operation bit permit it, one owned worker coalesces a
  memory-only saturating Unsigned count, keeps the earliest dropped timestamp,
  and waits for admission capacity without polling or delivery retries. The
  summary references the local Device as both source and target and omits other
  optional fields except Current_Value (the count) and Target_Timestamp. It
  bypasses object/priority filtering, uses the existing route and delivery mode,
  shares the 64-active bound, and retains instance-owned health and stop cleanup.
  Disabling the level/bit invalidates pending counts. Encoding/APDU-fit, DCC,
  policy/decode/budget failures, send/ACK failures, unknown operation outcomes,
  and summary failures are not counted. No ordinary-record queue, persistence,
  restart guarantee, or shared-endpoint audit producer is added.
  Confirmed delivery uses the existing invoke/transaction owner;
  unconfirmed delivery ends at transport send. An absent or invalid selected
  Reporter rejects server startup. For an existing Reporter, Reliability and its
  FAULT flag expose missing configuration and delivery failures. The profile has
  64 active delivery slots, a three-second total deadline, no retries or waiting outbox,
  and omits values above 32 encoded octets; overload never rolls back a write.
  This is not full Audit Reporter support: source reporting, remaining operations,
  per-object overrides, multi-Reporter overlap/lowest-instance selection, batching,
  forwarding/durable delivery, the public Device
  Audit_Notification_Recipient model, and Python parity remain deferred. #345
  stays open; no Audit Reporting BIBB or BTL qualification is claimed.
