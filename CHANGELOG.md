# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Entries for the next release are fragment files in [`changelog.d/`](changelog.d/), assembled here when a version is released. Add one per change instead of editing this file: [`changelog.d/README.md`](changelog.d/README.md) has the format, and `python3 scripts/changelog.py preview` shows the section they make.

## [0.11.0] - 2026-09-06

### Release highlights

This pre-1.0 release breaks Rust, Python and CLI APIs. Conformance remains
partial: the [conformance ledger](docs/conformance/bacnet-135-2020.json)
records the supported boundaries and the gaps, and this release is not a
full-conformance or BTL certification claim.

- Native BACnet/SC bounds its handshake, control sends, WebSocket resources
  and connection retirement, and validates heartbeats; WebSocket reader work
  continues in #525.
- Routed requests, peer APDU limits and segmented transactions follow the
  peer's identity and advertised capabilities.
- Intrinsic event history, exact BACnetTimeStamps, AcknowledgeAlarm
  correlation and ACK notifications keep committed transition state.
- Typed Rust and Python Audit clients join durable Audit Log storage, queries,
  notification receipt and duplicate detection; Audit Reporting BIBBs remain
  unclaimed.
- Python gains MS/TP configuration and local input Present_Value updates, File
  objects gain bounded resizing, logs gain exact ReadRange, and Staging gains
  explicit configuration.

### Migration notes

- Replace the stage-count `StagingObject::new` argument with a
  `StagingConfig`; see the [Rust example](docs/rust-api.md#building-control-7).
- Custom `AuditLogPersistence` implementations keep
  `AuditLogSnapshot::completed_receipts` in the same atomic commit as the
  records; the file backend writes schema v2 and reads v1 (see the
  [snapshot migration](docs/rust-api.md#audit-services)).
- CLI `ack-alarm` / `ack` need exact `--timestamp` and `--ack-time` values,
  and Python callers should use `acknowledge_alarm_request`, since the
  five-argument `acknowledge_alarm` is deprecated.
- GetEnrollmentSummary's `RecipientProcess::device` becomes
  `recipient: BACnetRecipient`, and the Audit request models and the raw
  Python `audit_log_query` signature changed; prefer the typed helpers.
- The Rust `AlertEnrollmentObject::new` and Python `add_alert_enrollment` take
  an explicit initial alert source (#291).
- A default `ServerConfig` advertises NO_SEGMENTATION and now refuses
  segmented traffic; set `segmentation_supported` to `BOTH` to accept it
  (#381).
- Drop uses of the withdrawn WASM crate, the Notification Forwarder and
  Channel constructors, and bundled-server WriteGroup execution.

### Added

- Application-owned `Present_Value` updates for in-service Analog, Binary and
  Multi-state Inputs through the server's `set_present_value_local`, in Rust
  and Python (#503, #510).
- Correlated AcknowledgeAlarm validation, lossless request construction
  (Python `acknowledge_alarm_request`), and ACK_NOTIFICATION delivery to the
  current Notification Class recipients (#132, #170, #175).
- Exact-delta Life Safety COV: Point and Zone subscriptions report only real
  Present_Value and Status_Flags changes (#177).
- Opt-in, application-owned execution of RESET, RESET_ALARM and RESET_FAULT on
  Life Safety Point and Zone objects (#177).
- Pre-start Python management of File objects: access method, payload copies
  and growth caps (#420).
- Bounded File_Size and Record_Count writes resize stream and record File
  objects (#417).
- The Event Log and both Trend Log object types give each record a stable
  sequence number and serve exact ReadRange By Position, By Sequence and By
  Time selection (#134, #339).
- BACnetLogStatus lifecycle records for the Event Log and both Trend Log
  object types (#189).
- Multi-state Input, Output and Value evaluate and recover their configuration
  Reliability, with a Rust `set_number_of_states` (#226).
- Optional `Reliability_Evaluation_Inhibit` on Analog, Binary and Multi-state
  Input, Output and Value objects (#232).
- Executable `PropertyMetadata` rows and the `BACnetObject::property_metadata`
  hook, starting with Time Value and Binary Input: the property-metadata core
  (#261).
- `bacnet_objects::file::FileStorage`, the channel AtomicReadFile and
  AtomicWriteFile use to reach a File object's contents, with growth caps for
  network writes (#397).
- `Time_Delay_Normal` on the nine intrinsic-reporting object types and on
  Event Enrollment (#225, #163).
- Enumeration parity with Clause 21: `LifeSafetyState` gains its tail, and new
  types such as `EscalatorOperationDirection`, `BinaryLightingPV`,
  `DoorValue`, `ProgramError` and `RestartReason` resolve by property (#253,
  #284).
- `BACnetClient::add_routed_device` registers a known routed peer, so requests
  follow its advertised limits (#372).
- Structured property values are writable: Multi-state Input Alarm_Values
  lists, DateTime Value Present_Value and Priority_Array entries, and
  Relinquish_Default on DateTime Value and DateTime Pattern Value (#182).
- Loop and Pulse Converter reference properties accept their Clause 21 wire
  forms through a strict `BACnetObjectPropertyReference` codec, and an empty
  setpoint reference clears the Loop's Setpoint_Reference (#182).
- Relinquish_Default is network-writable on the commandable object types, with
  a validated local `set_relinquish_default` (#270).
- Binary and Multi-state Input, Output and Value objects model
  Event_Time_Stamps and Event_Message_Texts (#235, #230, #258).
- `BackupAndRestoreState` and `Reliability` gain their missing named tail
  values (#246, #241).
- **Breaking (Rust API):** `FaultDetector` can no longer be built with a
  struct literal; use `FaultDetector::new(comm_timeout)`.
- **Rust API:** `BACnetObject::set_reliability_internal` is the trusted route
  for evaluated Reliability, separate from network writes; custom analog
  objects override it to keep fault detection working.
- Event_Detection_Enable on the seven other intrinsic-reporting types and
  Event Enrollment (default TRUE) and on Binary and Multi-state Output
  (default FALSE); writing FALSE holds the object at its initial event state,
  and the summary services skip it.
- `BACnetObject::is_writable_property`, `is_createable` and `is_deleteable`
  give PICS generation and dispatch one source of truth.
- `BACnetServer::write_local` is the server-owned local write, firing the same
  COV and event notifications as a network write.
- `BACnetObject::tick_intrinsic_reporting` and a 1-second server task advance
  Time_Delay countdowns.
- `BACnetObject::set_event_state_internal` persists an algorithmically derived
  Event_State, such as an Event Enrollment's.
- `ServerConfig::enable_event_enrollment` and `event_enrollment_interval_secs`
  configure Event Enrollment evaluation apart from fault detection.
- **Breaking (Rust API):** `evaluate_intrinsic_reporting` and
  `tick_intrinsic_reporting` return a `TransitionOutcome` that separates a
  transition from whether its notification may be sent.
- Binary Output and Multi-state Output gain Feedback_Value for the
  COMMAND_FAILURE algorithm.
- The event-property macros split into generic and analog halves, so Binary
  and Multi-state Outputs can be commissioned; Acked_Transitions stays
  read-only.
- `impl_intrinsic_reporting!` gains gated forms that take an
  Event_Detection_Enable field, and no ungated form remains.

### Changed

- **Breaking (CLI):** `ack-alarm` (and its `ack` alias) requires exact
  `--timestamp` and `--ack-time` values, and the five-argument Python
  `acknowledge_alarm` is deprecated with a warning.
- **Breaking (Rust API):** GetEnrollmentSummary's `RecipientProcess::device`
  becomes `recipient: BACnetRecipient`, and the service projects only
  object-owned event state with strict filters.
- **Breaking (wire):** WritePropertyMultiple follows ordered processing:
  writes before the first failure stay committed, and the error names the
  failed property (#242).
- `FileObject::set_data` and `set_records` update File_Size and Record_Count
  only for the selected access method (#397).
- The `bacnet-cli` argument definitions move into an `args` module to stay
  under the file-size cap (#213).
- The MSRV gate covers only the publishable crates, which lets `sysinfo` move
  to 0.39, and every other dependency is brought current; the MSRV stays 1.93.
- CI splits into a fast tier for PRs to dev and a heavy tier (cross-OS tests,
  MSRV, audit and deny) for main and tags.
- **Breaking (Python API):** `write_property_local` raises
  `BacnetProtocolError` for UNKNOWN_OBJECT and DUPLICATE_NAME instead of
  `RuntimeError`.
- The pinned development and CI toolchain moves to Rust 1.97.1; the MSRV stays
  1.93.

### Removed

- **Breaking:** the placeholder Notification Forwarder object and Python
  `add_notification_forwarder` are withdrawn (#188).
- **Breaking:** the placeholder Channel object, Python `add_channel` and
  inbound WriteGroup handling are withdrawn (#248).
- **Breaking (Rust API):** the uncalled `bacnet_server::intrinsic_reporting`
  module is removed (#237, #204).
- **Breaking:** the non-standard Alarm_Values and Fault_Values on Multi-state
  Output, and Fault_Values on Multi-state Input and Value with
  `set_fault_values`, are removed (#228).
- **Breaking (Rust API):** `bacnet_types::enums::LiftCarDoorStatus`, which
  matched no production, is removed (#245).
- **Breaking (Rust API):** the ungated three-ident arm of
  `impl_intrinsic_reporting!` is removed.
- The `bacnet-wasm` crate, its docs and its CI jobs are removed.
- The BACnet/SC WASM conformance evidence is withdrawn, narrowing those claims
  to native only.

### Fixed

- The deprecated GetAlarmSummary server selects only active ALARM candidates,
  and returns OPERATIONAL_PROBLEM instead of made-up defaults for unreadable
  fields (#172).
- GetEventInformation projects each event-initiating object as one strict
  snapshot, keeps all three BACnetTimeStamp choices, and takes priorities from
  one Notification Class (#128, #206).
- Binary Lighting Output treats WARN, WARN_OFF, WARN_RELINQUISH and STOP as
  operations rather than stored values, and its Relinquish_Default takes only
  OFF or ON (#283).
- In-service network writes to a Pulse Converter's Present_Value are refused;
  out-of-service simulation writes still work (#280).
- **Breaking (wire, Rust and Python API):** Alert Enrollment serves its
  bounded Table 12-61 property model, with a read-only Present_Value naming
  the latest alert source, and its constructors take an initial source (#291).
- Exact duplicate Confirmed-Request messages are discarded before decoding,
  under bounded, process-local tracking (#177).
- `bacnet file-read` decodes AtomicReadFile ACKs strictly and writes the
  payload instead of the raw ACK, and `atomic_read_file_decoded` validates the
  reply (#419).
- File payload changes stamp Modification_Date from the database clock and
  clear Archive (#416).
- Reliability evaluation belongs to each object through an opt-in hook; Analog
  Input and Value can opt into FAULT_OUT_OF_RANGE limits, and Min_Pres_Value
  and Max_Pres_Value no longer act as fault limits.
- **Breaking (Rust API):** NotificationParameters codecs are corrected for
  complex event values, AccessEvent credentials, the omitted choice and
  ChangeOfTimer fields, and `NoneParams` is gone (#351).
- Device `Active_COV_Subscriptions` reads return every field of each
  BACnetCOVSubscription (#183).
- Escalator Power_Mode, Operation_Direction, Escalator_Mode, Energy_Meter,
  Fault_Signals and Passenger_Alarm accept validated writes in and out of
  service (#401).
- `AtomicWriteFileRequest::decode` requires exactly Record Count records
  (#418).
- AtomicReadFile and AtomicWriteFile reach the File object's stored contents,
  with correct start, append and end-of-file handling (#397).
- AtomicReadFile and AtomicWriteFile refuse a non-File object with
  INCONSISTENT_OBJECT_TYPE, and AtomicWriteFile on a read-only File answers
  SERVICES / FILE_ACCESS_DENIED (#398, #399).
- Confirmed client requests stop the request timer once segment zero of a
  segmented ComplexACK arrives, and a receive segment timeout reclaims its
  state promptly (#379, #380).
- Devices configured for segmented transmit advertise Max_Segments_Accepted 1
  (#379).
- Server segmented transactions identify a routed peer by its SNET/SADR, so
  its segments may arrive through another router (#384).
- Segmented receivers use the corrected modulo-256 duplicate-in-window rule
  (#383).
- The client refuses locally to segment a request to a peer that advertises it
  can't receive segments (#371).
- DeviceTable no longer confuses a router with the routed peers behind it, and
  duplicate address matches pick the freshest row (#372).
- The Escalator stores Operation_Direction and Escalator_Mode as typed
  enumerations and accepts every named and proprietary value (#284, #400).
- The server enforces a File object's File_Access_Method for AtomicReadFile
  and AtomicWriteFile (#287).
- **Breaking (Rust and Python API):** Audit notification and AuditLogQuery
  wire models follow the Clause 21 productions, typed Python helpers decode
  queries, and Audit Log objects add durable storage, queries and authorized
  receipt (#345, #511, #458, #463, #466, #512, #535).
- **Breaking (Rust and Python API):** COV-multiple wire models match their
  productions, with mandatory booleans, cardinality checks and typed
  timestamps, and Python's `subscribe_cov_property_multiple` requires
  `issue_confirmed_notifications` (#342).
- **Breaking (Rust and Python API):** GetEnrollmentSummary uses its own Event
  State Filter values and full Unsigned Notification Class fields, and Python
  takes `EnrollmentSummaryEventStateFilter` (#358, #176).
- Test-only server dispatch constants compile only for tests (#359).
- **Rust API:** client-mode responders reject unhandled confirmed requests,
  B/IP and B/IPv6 read each datagram's real destination, and B/IPv6 VMAC
  handling follows Annex U; `ReceivedNpdu` and `ReceivedApdu` gain group
  fields (#374).
- Confirmed-Request `max-segments-accepted` rounds down to a valid rung
  instead of claiming more than 64 (#365).
- Confirmed event notifications reach remote-network recipients, correlating
  the routed acknowledgment and learning the router (#375).
- Server segmented request reassembly stops at 256 segments with a
  BUFFER_OVERFLOW Abort instead of wrapping (#364).
- A client reassembly session ends with its transaction (#367).
- A stale SegmentAck no longer kills a healthy segmented request, and negative
  acks continue after the last accepted segment (#368).
- **Breaking (wire):** the server honours its segmentation advertisement both
  ways, so a default server (NO_SEGMENTATION) refuses segmented traffic until
  `segmentation_supported` is set (#381, #377).
- Event notifications carry the network priority their event priority maps to
  (#187).
- Notifications to a remote-network unicast recipient go out as a routed local
  broadcast instead of being skipped (#186).
- A recipient spelled with the link's literal broadcast MAC resolves as a
  broadcast, through the new `TransportPort::is_broadcast_mac` (#360).
- Replies to a routed peer, such as SegmentACKs and Aborts, carry the
  request's source back as their destination (#366).
- Routed confirmed requests honour the routed peer's advertised Max APDU
  Length Accepted (#362).
- Alert Enrollment exposes Event_State and Acked_Transitions and resets them
  when Event_Detection_Enable goes FALSE (#205).
- Object snapshot hooks stay as an object-local surface, but
  WritePropertyMultiple now keeps successful prefix writes instead of
  restoring them (#209, #289).
- The Event Enrollment evaluator honours Time_Delay and Time_Delay_Normal
  (#163).
- Event Enrollment same-state transitions store the specific state and
  maintain Acked_Transitions, and CHANGE_OF_STATE re-indicates between alarm
  values (#166).
- Event Enrollment CHANGE_OF_VALUE compares against a detection baseline
  instead of the absolute value (#137).
- Event Enrollment algorithms recover from an Event_State the current
  algorithm can't reach, and CHANGE_OF_BITSTRING no longer reports OFFNORMAL
  on a prefix match.
- Event Enrollment alarms can be acknowledged, and a detection-disabled
  enrollment refuses with NO_ALARM_CONFIGURED.
- WriteProperty and WritePropertyMultiple decode the whole property value,
  refusing partial or empty payloads with INVALID_DATA_ENCODING (#182).
- Pulse Converter and Averaging PICS writability matches what their write
  paths accept (#182).
- Reliability write validation derives from `Reliability::ALL_NAMED`, so new
  named values are accepted without a second edit (#252).
- Indexed reads of the analog types' Event_Time_Stamps and Event_Message_Texts
  return one element (#235).
- The Device's Protocol_Services_Supported comes from the services the server
  actually executes (#192).
- **Breaking (wire):** bit strings of up to eight bits encode most significant
  bit first, which reverses Event_Enable, Acked_Transitions and the
  Recipient_List day and transition masks for peers still on the old bytes
  (#203).
- **Breaking (wire):** `FileAccessMethod`'s values were swapped; RECORD_ACCESS
  is now 0 and STREAM_ACCESS 1, so a stored raw File_Access_Method value needs
  remapping (#273).
- **Breaking (Rust API):** `DoorAlarmState::LOCK_FAULT` is renamed
  `LOCK_DOWN`, with its value unchanged (#274).
- **Breaking (Rust API):** the invented `StagingState` enumeration is removed;
  Present_Stage is an Unsigned index into Stages (#275).
- The Averaging Object_Property_Reference write is strict about its members
  and refuses references to other devices (#182).
- Loop and Schedule refuse in-service Reliability writes and validate
  out-of-service ones, and Trend Log refuses them entirely (#240).
- **Breaking (wire):** Notify_Type writes must name a defined value, and
  Event_Enable and Limit_Enable writes need their canonical encoding (#255).
- CHANGE_OF_STATE alarm parameters are reachable over BACnet: Binary Input and
  Value serve Alarm_Value, and Multi-state Alarm_Values is edited with the
  list services (#228).
- Binary Input, Binary Value, Multi-state Input and Multi-state Value expose
  writable Event_Enable, Notification_Class, Notify_Type and Time_Delay, so
  their notifications can be commissioned (#229).
- A refused Out_Of_Service write changes nothing.
- **Breaking (Rust API):** a change from one fault Reliability to another
  re-enters FAULT and notifies, and the detectors gain a public
  `fault_reliability` field (#217).
- The server's fault detector no longer overwrites the Reliability of an
  out-of-service analog object.
- Binary Output and Multi-state Output apply the COMMAND_FAILURE event
  algorithm, opt-in through Event_Detection_Enable (#222).
- **Breaking (Rust API):** a notification takes its Event Type from the
  algorithm the object runs, and `TransitionOutcome` gains `event_type`
  (#210).
- Every Event_State-to-transition-bit decision goes through one classifier,
  `EventTransition::for_target_state`, which fixes a latent inversion.
- **Breaking (Rust API):** Reliability drives Event_State, so FAULT and
  TO_FAULT transitions become reachable, and the detectors take a
  `reliability` argument (#167, #200).
- FAULT transitions report Event Type CHANGE_OF_RELIABILITY.
- PICS writable-property flags for the nine core input, output and value types
  mirror their write paths, and the createable and deleteable flags match what
  CreateObject and DeleteObject accept.
- Object_Name writes go through the name index, refusing duplicates with
  DUPLICATE_NAME and freeing the old name.
- Local writes fire the same COV and event notifications as network writes,
  through `BACnetServer::write_local`.
- A commandable Present_Value write in a WritePropertyMultiple prefix keeps
  its priority slot if a later write fails.
- The intrinsic detectors honour Time_Delay, splitting evaluation into a
  per-write `probe` and a periodic `tick`.
- Multi-state constructors refuse zero states.
- EventNotification takes each transition's Priority and Ack_Required from the
  referenced Notification Class (ASHRAE 135-2020 Clause 12.21).
- Notification Class recipient day bits and time windows follow one
  convention, with overnight windows and the device's local time (ASHRAE
  135-2020 Clause 12.21 / Clause 21.6).
- **Breaking (wire):** a Recipient_List address recipient keeps its network
  number (ASHRAE 135-2020 Clause 12.21 / Clause 21.6).
- **Breaking (Rust API):** Event Enrollment's Event_Parameters is a structured
  `BACnetEventParameter` (ASHRAE 135-2020 Clause 12.12 (Event_Parameters) /
  Clause 21.6 (BACnetEventParameter)) that the evaluator uses; older raw
  values still evaluate.
- Event Enrollment's Event_State is read-only over the network, with a
  separate internal lifecycle path.
- Event Enrollment evaluation has its own configuration, apart from the
  fault-detection switch.
- The release gate waits on every Tier 1 CI job, the file-size cap and MSRV
  included.
- Event_Enable gates only notification distribution, so a suppressed
  transition still updates Event_State.

## [0.10.1]

### Added

- `BACnetClient::device_events()` reports device discovery, updates and loss,
  alongside the `discovered_devices()` snapshot.
- Client builder setters for APDU retries, accepted segments,
  segmented-response acceptance and proposed window size.
- `BACnetClient` COV and COV-property subscribe and unsubscribe helpers that
  route through discovered devices, plus a managed finite subscription that
  renews before expiry.
- COV notifications carry source metadata and delivery kind, with a
  configurable confirmed-notification ACK policy.
- `ScTransport::connection_state_changes()` lets BACnet/SC consumers await
  link-state changes without polling.
- Typed BACnet/SC connect errors (`ScConnectError`) keep BVLC-Result NAK
  details and tell dial, TLS, handshake and subprotocol failures apart.
- `ScClientBuilder::device_uuid(...)` and the CLI `--sc-vmac` /
  `--sc-device-uuid` options provision a stable SC identity.
- `generate_random48_vmac()` and `is_valid_random48_vmac()` mint and validate
  Random-48 VMACs.

### Fixed

- `ScClientBuilder` and the SC CLI fail fast on missing or reserved SC
  identity instead of connecting with an all-zero VMAC.
- Negotiated SC hub Max-NPDU and BVLC limits reach
  `ScTransport::max_apdu_length()` and client segmentation, exposed by
  `transport_max_apdu_length()`.
- SC handshake timeouts return `Error::Timeout`, and malformed BVLC-Result
  failures typed `ScConnectError` values.
- SC reconnect, failover and primary restore re-dial the WebSocket instead of
  reusing a torn-down one.
- Dropping a client or SC transport aborts its receive tasks and closes its
  sockets, while graceful shutdown still sends Disconnect-Request.
- The device table purges stale entries on its own interval, without `Instant`
  underflow on fresh Windows runners.
- The server sends the initial COV notification after accepting a
  subscription.
- SubscribeCOVPropertyMultiple encodes its lifetime and max-delay fields in
  standard order, validates them, and expires server-side subscriptions.
- `bacnet-client` property method rustdoc describes the right methods.
- `ObjectIdentifier` documents wildcard instances and gains an
  addressable-object constructor that refuses the wildcard.
- The client's COV notification channel capacity is configurable, still 64 by
  default.

## [0.10.0]

### BACnet/SC - Connection Resilience (ASHRAE 135-2020 Annex AB.6.2, AB.6.3)

- A `NODE_DUPLICATE_VMAC` NAK reseeds a Random-48 VMAC and reconnects, and a
  hub lets a device with a known UUID reclaim its stale session.
- Failover follows mid-life reconnect exhaustion, and the primary hub is
  probed and restored afterwards.
- Heartbeats go out only on an idle link and must correlate to the outstanding
  request.
- Fatal NAKs, receive errors and reconnect exhaustion tear the transport down
  to `Disconnected`.

### BACnet/SC - Protocol Conformance (Annex AB.2, AB.3)

- BVLC-Result payloads are parsed, and malformed option chains rejected.
- SC data options are encoded, exposed as `ReceivedNpdu::data_attributes`, and
  unsupported must-understand options rejected.
- The hub checks the exact ConnectRequest length, enforces Max-BVLC-Length and
  stamps originating VMACs itself.
- TLS 1.3 is enforced, and `ErrorCode` gains constants 139 to 151,
  `NODE_DUPLICATE_VMAC` among them.

### BACnet/IP - Annex J

- The BIP socket binds `INADDR_ANY` so subnet and limited broadcasts arrive on
  Linux.
- Forwarded-NPDU rebroadcast loops and Original-Broadcast echoes are
  suppressed.
- BBMD forwarding failures NAK, FDT entries expire on a timer, the BDT
  persists across restart, and management ACKs and ACLs are corrected.

### WASM (browser bindings)

- BACnet/SC heartbeats, disconnect handling and data attributes in the WASM
  layer.

### Server

- `BACnetServer::i_am_broadcaster()` / `broadcast_i_am()` and
  `BipServerBuilder::vendor_id(u16)` for host-driven I-Am.

### Dependencies

- `pyo3` 0.29, resolving audit advisories.

## [0.9.0]

### Spec Compliance - Codec Strictness (ASHRAE 135-2020 Clauses 20.1.2.7, 20.1.2.8, 20.1.6.x)

- Codecs validate ConfirmedRequest max-APDU and SegmentACK window fields,
  refuse BVLL lengths past 16 bits, and reject wrong-length primitives and
  trailing bytes (Findings 4, 6, 7).

### Spec Compliance - Confirmed Notification TSM (ASHRAE 135-2020 Clause 5)

- Confirmed EventNotifications use the server TSM with timeouts and retries,
  keyed by peer and invoke ID (Finding 8).

### Spec Compliance - Segmentation (ASHRAE 135-2020 Clauses 5, 20.1.2.4, 20.1.2.5, 20.1.6.x)

- `split_payload` refuses more than 256 segments, and segmented ComplexACKs
  stay within the segment count the client accepts (Findings 1, 2).
- Server segmented receive validates the window, ACKs at window boundaries and
  NAKs gaps, and NAK retransmission resumes at the next segment (Findings 3,
  5).
- Routed confirmed requests segment when they exceed the local APDU limit,
  with responses matched by their routed key (Finding 9).

### Performance

- Notification sends freeze their payload buffers instead of copying them
  (Finding 10).

### Changed

- **API break:** APDU, BVLL and BVLC encoders and `split_payload` return
  `Result`.
- **Behavior change:** primitive decoders reject malformed encodings with
  trailing bytes.

### Engineering — CI guardrails

- Workspace lints are centralized (`unsafe_code` denied outside documented FFI
  sites), the toolchain is pinned, and CI adds `cargo audit`, a secret scan,
  the file-size cap and `--locked`.

### Engineering — Modularity (700 LOC cap)

- 34 source files split into modules so every file is under the 700-line cap,
  now enforced strictly, with import paths unchanged.

### Workspace reorganization

- **`bacnet-gateway`** moved to
  [`jscott3201/rusty-bacnet-mcp`](https://github.com/jscott3201/rusty-bacnet-mcp)
  and **`bacnet-btl`** to
  [`jscott3201/rusty-bacnet-btl-harness`](https://github.com/jscott3201/rusty-bacnet-btl-harness),
  leaving this workspace to the protocol stack.

### Removed (from this workspace)

- The `bacnet-btl` and `bacnet-gateway` crates, their docs and the BTL Docker
  assets.

### Notes

- Library APIs changed from 0.8.1 where noted above; the Python and WASM
  bindings and the CLI are unchanged.

## [0.8.1]

### Security

- `rustls-webpki` 0.103.13 and `rand` 0.10.1 and 0.9.4 address
  [RUSTSEC](https://rustsec.org/) advisories, including
  [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097).

### Fixed

- **bacnet-gateway** uses the configured BIP port for its client transport
  instead of an ephemeral one.
- **bacnet-client** gates its `Ipv6Addr` import behind `ipv6`, and
  **bacnet-gateway** drops an unused import.

### Documentation

- **Benchmarks.md** is refreshed with a clean run of all nine Criterion
  suites.

## [0.8.0]

### Spec Compliance — BBMD & Router (ASHRAE 135-2020 Annex J, Clause 6)

A review of the BBMD and router found 22 spec compliance issues, all fixed.

#### Router — Congestion & Reachability (Clause 6.6.3)

- Routers refuse traffic to busy (reason 2) or unreachable (reason 1)
  networks, Router-Busy clears after 30 s, busy and available messages are
  re-broadcast, and unknown messages are rejected (reason 3).
- `RouterTable` gains busy, available and unreachable marking with timestamped
  auto-clear.

#### Router — Route Management (Clause 6.6.3.2/3)

- I-Am-Router-To-Network is always re-broadcast, route updates from other
  ports are accepted with flap detection, and active routes are refreshed on
  use.

#### Router — Network Messages (Clause 6.4)

- Initialize-Routing-Table-Ack and Network-Number-Is get handlers, and
  security messages are no longer rejected.

#### BBMD (Annex J)

- The BBMD includes itself in its BDT, non-BBMD Forwarded-NPDUs use the
  originating address, Distribute-Broadcast-To-Network and short registrations
  NAK, and the BDT can persist to a file.

#### TSM (Clause 5.4)

- A drop guard frees the invoke ID when a confirmed request's task is
  cancelled.

### Spec Compliance — Transport Layer (ASHRAE 135-2020 Clauses 7-9, Annexes J, U, AB)

A review of all five transports found 34 spec compliance issues: 31 fixed and 3 deferred.

#### MS/TP — State Machine (Clause 9.5)

- MS/TP uses the right token-loss timeout and per-station offset, finishes on
  a reply, validates the reply source, handles ReplyPostponed, and discards
  frames after an inter-byte gap.

#### BACnet/IPv6 — VMAC & Address Resolution (Annex U)

- Virtual-Address-Resolution frames have the right sizes, unicast uses a
  learned VMAC table, and B/IPv6 adds address resolution, a configurable
  multicast scope and foreign-device registration.

#### BACnet/SC — Client (Annex AB)

- Heartbeat-ACKs omit VMACs, BVLC-Results parse their result code,
  Connect-Accept message IDs are checked, `stop()` sends Disconnect-Request,
  and the hub's Device UUID is stored.

#### BACnet/SC — Hub (Annex AB)

- The hub requires a full ConnectRequest, NAKs early and unknown messages,
  relays broadcasts in parallel, enforces each client's max NPDU, and probes
  idle clients with heartbeats.

#### BACnet/SC — TLS (Annex AB.7.4)

- Every TLS client configuration requires TLS 1.3.

#### Ethernet — LLC Commands (Clause 7.1)

- XID and TEST commands are handled, the BPF filter admits them, and transient
  receive errors no longer stop the loop.

#### BIP — Foreign Device (Annex J)

- Foreign-device registration and broadcast NAKs are logged as errors.

#### Cross-Cutting Transport Improvements

- A second `start()` returns an error instead of leaking, "not started" is
  `Error::Transport(NotConnected)` everywhere, receive loops no longer stall
  on slow consumers, `stop()` clears state, and `bip6` sits behind the `ipv6`
  feature.

### Spec Compliance — Stack-Wide (ASHRAE 135-2020 Clauses 5, 6, 12, 13, 15, 16, 20)

A review of the other layers found 43 spec compliance issues; every critical, high and medium one is fixed.

#### Encoding & APDU (Clause 20)

- SegmentAck window sizes clamp to 1 to 127, and reserved max-APDU values log
  a warning.

#### Types & Enums (Clause 21)

- LifeSafetyOperation values are reordered, and LifeSafetyMode OEO values, a
  DaysOfWeek type and 11 BACnetPropertyStates variants are added.

#### Services (Clauses 13-16)

- TextMessage tags and the ReinitializeDevice password size are corrected,
  EventNotification gains `message_text`, and GetEnrollmentSummary gains its
  enrollment filter.

#### Objects (Clause 12)

- The nine event-capable types compute IN_ALARM, Value_Source tracking fields
  are added, and the trait gains `set_overridden()`.

#### Client (Clause 5.4)

- Segmented response reassembly acknowledges per window, handles duplicates
  and NAKs correctly and aborts when segmented responses aren't accepted, and
  the device table purges stale entries.

#### Server

- COV `ack_required`, DCC DISABLE, COV-property cancellation, RPM device
  wildcards, GetEnrollmentSummary priorities, Event_Enable reads and schedule
  times are corrected.

#### Network (Clause 6)

- Routers deliver remote broadcasts locally, pass network messages through,
  forward proprietary messages and report the real port in
  Init-Routing-Table-Ack.

### Python Bindings Improvements

- Rewritten type stubs, time synchronization, directed Who-Is, auto-routing
  reads and writes, `add_device()`, `discover()`, more `PropertyValue`
  constructors, structured error attributes, and DCC and reinitialize
  passwords.

### Added

- **New crate: `bacnet-gateway`**, an HTTP REST and MCP server for BACnet
  networks.
- `LoopbackTransport` for in-process composition, RS-485 GPIO direction
  control, concurrent multi-device client batches, client auto-routing and
  concurrent server dispatch.
- Architecture documentation and expanded API guides.

### Changed

- Dependencies are updated, resolving aws-lc-sys and rustls-webpki security
  advisories.

### Removed

- The Java/Kotlin bindings and their CI jobs.

## [0.7.2]

### Added

- **New crate: `bacnet-gateway`**, an HTTP REST API and MCP server with
  discovery, property access, local object management, a BACnet knowledge base
  and bearer-token authentication.
- `LoopbackTransport` and `AnyTransport::Loopback` for in-process composition.

## [0.7.1]

### Fixed

- The maturin wheel build works again without the invalid `python-source`
  setting.

## [0.7.0]

### Spec Compliance (ASHRAE 135-2020)

A seven-area compliance review brought more than 55 fixes across the stack.

#### BACnet/SC (Annex AB)

- SC control flags, Connect payloads (now with the Device UUID),
  control-message VMACs, BVLC-Result NAKs, header options and the broadcast
  VMAC follow Annex AB; the hub rewrites unicast VMACs, non-binary WebSocket
  frames close with 1003, and reconnects back off from 10 to 600 s.

#### BACnet/IPv6 (Annex U)

- B/IPv6 function and result codes, the Original-Unicast and Forwarded-NPDU
  headers and the FDT grace period are corrected, and the receive buffer grows
  to 2048 bytes.

#### Network Layer (Clause 6)

- I-Am-Router-To-Network is broadcast, final-hop delivery strips DNET, invalid
  SNETs and misaddressed messages are refused, and reject reasons are
  corrected.
- Routers re-broadcast I-Am-Router, forward Who-Is-Router, track reachability
  through Router-Busy and Router-Available, relay rejects and answer table
  queries.

#### Object Model (Clause 12)

- Property_List leaves out the four standard properties, Status_Flags is
  computed, and Object_Name is writable everywhere.
- Device gains Device_Address_Binding and Max_Segments_Accepted, commandable
  objects gain Current_Command_Priority and Value_Source tracking, and new
  detectors and event properties cover the binary, multi-state and analog
  objects.

#### Services (Clauses 13-16)

- SubscribeCOV lifetime 0 means indefinite and requires COV support,
  TextMessage, AcknowledgeAlarm, DCC, ReadRange and WriteGroup follow their
  clauses, RPM reports per-property encode errors, and COV subscriptions are
  keyed by property.

#### MS/TP (Clause 9)

- MS/TP fixes T_slot, initialization, token passing, Poll-For-Master, reply
  timeouts and NO_TOKEN arbitration, and adds EventCount and T_turnaround.

#### APDU Encoding (Clauses 5, 20)

- Window sizes clamp to 1 to 127, 256 segments are allowed, character set
  names are corrected, and the TSM gains an APDU_Segment_Timeout.

### BTL Compliance Test Harness

#### Test Harness

- **New crate `bacnet-btl`**: a BTL Test Plan 26.1 harness with 3808 tests
  across 13 sections, self-test, external-device and serve modes over BIP or
  SC, and Docker topologies.

#### Stack Compliance Fixes Found by BTL Tests (~40 fixes)

- Missing Device, Schedule, Lighting, Staging and event properties, wildcard
  Device reads, COV support on 11 more object types, commandable pattern
  values, and the new Color and Color Temperature objects.

### Code Review Fixes

#### Critical

- A segmented-send panic, silent u16 and u32 truncation in encoders, and a
  server dispatch `expect()` are fixed.

#### Security

- The I-Am-Router broadcast loop, routing-table bounds and reserved networks,
  BDT size panics, and SC hub pre-handshake limits and reserved VMACs are
  handled.

#### Concurrency

- TLS WebSocket lock ordering is fixed, SC hub broadcast relay is bounded, and
  COV delivery uses oneshot channels instead of polling.

#### Correctness

- COV subscription keys, DeleteObject COV cleanup, event invoke IDs,
  day-of-week numbering and SubscribeCOVProperty content are corrected, with
  added bounds checks and overflow guards.

### New Server Handlers

- GetAlarmSummary, GetEnrollmentSummary, Confirmed and Unconfirmed
  TextMessage, LifeSafetyOperation, WriteGroup and
  SubscribeCOVPropertyMultiple handlers, wired into dispatch.

### Python Bindings

- `rusty_bacnet.pyi` type stubs and a `py.typed` marker for IDEs and type
  checkers.

### Other

- Trend Log polling state moves into the server, LoopbackSerial buffers excess
  bytes, and Init-Routing-Table ACKs encode only `count` entries.

## [0.6.4]

### Changed

- BIP and confirmed-request internals are refactored, BBMD state is created at
  `start()` with the bound address, and `register_foreign_device` is renamed
  `register_foreign_device_bvlc`.

### Added

- `bvlc_request` refuses concurrent management requests, and the
  Forwarded-NPDU source MAC difference between BBMD and foreign-device modes
  is documented.

## [0.6.3]

### Added

- Interactive shell session state (`target`, `status`), BBMD auto-renewal, the
  remaining commands (`ack-alarm`, `time-sync`, `create-object`,
  `delete-object`, `read-range`), `discover --bbmd`, colored output and
  discovery progress.

### Changed

- Shell output helpers are deduplicated, dead code removed, and the BIP shell
  separated for BBMD commands.

### Fixed

- Repeated interactive `discover --target` finds devices again, and an unused
  import is gone.

## [0.6.2]

### Added

- CLI `discover --target`, `--bbmd` and `--dnet`, backed by
  `who_is_directed()`, `who_is_network()` and
  `NetworkLayer::broadcast_to_network()`, also in the shell.

### Fixed

- Backspace in the interactive shell deletes characters visually.

## [0.6.1]

### Added

- `bacnet capture` for live packet capture and pcap analysis with a BACnet
  frame decoder, behind the `pcap` feature; pre-built CLI binaries for Linux,
  macOS and Windows; and `docs/CLI.md`.

### Fixed

- Stale `nicegates` org references are replaced with `jscott3201`.

## [0.6.0]

### Added

- BBMD client API on `BipTransport` and `BACnetClient` (`read_bdt`,
  `write_bdt`, `read_fdt`, `delete_fdt_entry`, `register_foreign_device`),
  with working CLI `bdt`, `fdt`, `register` and `unregister` commands and
  table or JSON output.
- BACnet/IPv6 CLI support (`--ipv6`, `--ipv6-interface`, `--device-instance`,
  bracketed targets) and `Bip6ClientBuilder`.

### Changed

- BBMD management commands are limited to the BIP transport.

## [0.5.5]

### Fixed

- The Java/Kotlin Gradle publish URL points at the right GitHub org.

## [0.5.4]

### Fixed

- The WASM npm package has the `repository` field npm provenance needs.

## [0.5.3]

### Fixed

- Clippy's `io_other_error` in the Ethernet transport and `inherent_to_string`
  in the WASM bindings (Rust 1.93).

### Changed

- CHANGELOG entries for patch releases unblock the release pipeline.

## [0.5.2]

### Fixed

- Clippy's `io_other_error`: the Ethernet transport uses
  `std::io::Error::other()`.

## [0.5.1]

### Added

- Kotlin examples and a JMH benchmark suite, with results in Benchmarks.md.

### Fixed

- `Display` for `JsObjectIdentifier`, UniFFI's Tokio runtime on async blocks,
  and the benchmarks crate version.

### Changed

- CLAUDE.md covers the Java/Kotlin build.

## [0.5.0]

### Added

- **Java/Kotlin bindings:** the `bacnet-java` crate through UniFFI 0.31, with
  an async client, server object builders and COV streams, published as a
  multi-platform JAR to GitHub Packages.
- CI builds the native libraries on five platforms and publishes the JAR on
  release tags.

## [0.4.0]

### Added

- **WASM/JavaScript support:** the `bacnet-wasm` crate, a BACnet/SC thin
  client for browsers with service codecs and TypeScript definitions.
- CI checks the WASM build and publishes the npm package on release tags.

## [0.3.0]

### Fixed

- CI builds aarch64 Linux wheels on a native ARM64 runner instead of
  cross-compiling.

## [0.2.0]

### Changed

- Client-server integration tests move to `bacnet-integration-tests`, breaking
  the circular dev-dependency that blocked publishing.

### Fixed

- CI builds aarch64 Linux wheels under QEMU without sccache, and publishes
  crates in a simpler order.

## [0.1.5]

### Fixed

- CI publishes the server and client in the right order and builds aarch64
  Linux wheels.

## [0.1.4]

### Fixed

- Every workspace dependency declaration carries a version, so the crates
  publish.

## [0.1.3]

### Fixed

- Cargo Deny allows MPL-2.0 for `serialport`, and an Ethernet test imports
  `TransportPort`.

## [0.1.0]

Initial release of the Rusty BACnet protocol stack implementing ASHRAE 135-2020.

### Protocol Stack

- Application, network and transport layers with full BACnet encoding, two-way
  APDU segmentation and NPDU routing with hop counts.

### Transports

- BACnet/IP with BBMD, BACnet/IPv6, BACnet/SC with its hub, MS/TP and Ethernet
  (the last two Linux only).

### Services (24 modules)

- Property access, object management, discovery, COV, file access, alarm and
  event, device management and list operations, plus PrivateTransfer,
  ReadRange, TextMessage, VirtualTerminal, WriteGroup, LifeSafety and Audit.

### Object Types (62)

- The standard object types, from the analog, binary and multi-state families
  through access control, elevator, life safety, lighting, scheduling,
  trending and audit to the twelve value types.

### Client

- An async Tokio client with a transaction state machine, 31 service methods,
  segmentation, discovery with a device cache, retries, and `bip_builder()`,
  `sc_builder()` and `generic_builder()`.

### Server

- An async server dispatching 17 services over 62 object types, with COV,
  intrinsic reporting, event enrollment, fault detection, schedules, trend
  logging, DCC and PICS generation.

### Network Layer

- Routing with RouterTable, a multi-port BACnetRouter, priority queuing and
  hop-count loop prevention.

### Python Bindings (PyO3)

- An async API with `BACnetClient`, `BACnetServer` and `PyScHub`, typed enums,
  COV iteration and BIP, IPv6 and SC transports, published to PyPI as
  `rusty-bacnet`.

### Testing & Quality

- 1,682 tests, CI on Linux, macOS and Windows, zero-warning Clippy and
  `cargo-deny`.

### Benchmarks

- Nine Criterion suites, four Python mixed-mode benchmarks and a Docker
  benchmark environment.

### Examples

- Rust and Python examples for BIP, IPv6, SC, COV and device management, plus
  a Docker Compose deployment.
