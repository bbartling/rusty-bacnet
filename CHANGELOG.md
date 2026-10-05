# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Entries for the next release are fragment files in [`changelog.d/`](changelog.d/), assembled here when a version is released. Add one per change instead of editing this file: [`changelog.d/README.md`](changelog.d/README.md) has the format, and `python3 scripts/changelog.py preview` shows the section they make.

## [0.12.0] - 2026-10-05

### Release highlights

This pre-1.0 release breaks Rust, Python and CLI APIs and changes some
on-the-wire behaviour. Before moving a v0.11.0 integration, read the
[upgrade guide](https://jscott3201.github.io/rusty-bacnet/project/upgrading/),
which groups what changes by area; the migration notes below give the exact
replacements. Conformance remains partial, and this release is not a
full-conformance or BTL certification claim.

- Objects do more of their own work: Command and Channel run their actions
  and member writes, in other devices too; the server executes WriteGroup;
  Lighting Output carries out fades, ramps, steps and warnings; Trend Log
  Multiple polls its members; and the Notification Forwarder is new.
- Event notifications reach a Device recipient the server holds no binding
  for through a targeted Who-Is, and the Device serves the bindings it holds
  in Device_Address_Binding.
- Access control, life safety, Schedule and log objects serve many more of
  their standard properties. Notification Class, Notification Forwarder and
  Access Rights can keep what peers write across a restart, saved off the
  database lock.
- Python reads constructed values typed, and its value and enumeration
  classes copy and pickle.
- Releases are built natively for Linux (x86_64, aarch64), macOS (arm64,
  Intel) and Windows. The Linux CLI needs glibc 2.17 and no libpcap, wheels
  cover CPython 3.11 to 3.14, and `bacnet-endpoint` and `bacnet-cli` are new
  on crates.io; see the
  [installation page](https://jscott3201.github.io/rusty-bacnet/start/installation/).
- The terminal UI (`bacnet tui`) stays behind the opt-in `tui` feature until
  0.13.0.

### Added

- **Rust and Python API:** an SC hub can bind verified leaf certificate
  SHA-256 identities to provisioned UUID and VMAC groups (#800).

- Standalone clients passively learn and answer local Network Number controls
  on transports that opt in (#879). ([a8194c1](https://github.com/jscott3201/rusty-bacnet/commit/a8194c1425cd192d59cee2ff010a296ff26ad6df))

- **Python and Rust API:** `rusty_bacnet.list_serial_ports()` and
  `bacnet_transport::mstp_serial::available_ports()` list the serial ports the
  OS reports, for MS/TP (#951).

- **Rust API:** `BACnetClient::transport()` borrows a built client's
  transport, so SC link state, B/IP counters and BBMD state, and MS/TP
  diagnostics are reachable after `build()` (#956). ([5e9e676](https://github.com/jscott3201/rusty-bacnet/commit/5e9e6763b3224ff7dfc2e19ad7a6c9a132587a3a))

- `bacnet tui` opens a read-only, full-screen terminal UI with a live device
  table and a Who-Is form, behind the opt-in `tui` feature (`--features tui`). Release builds leave it
  out until the terminal UI ships (#961, part of #975). ([6d866b6](https://github.com/jscott3201/rusty-bacnet/commit/6d866b683f92c23fd06a0ed0d2ab4e5e17f4ccc8))

- Staging objects support COV with a COV_Increment, reporting Present_Value,
  Status_Flags and Present_Stage, and the new `cov_reported_properties` hook
  lists what a report carries (#988). ([943b8fa](https://github.com/jscott3201/rusty-bacnet/commit/943b8fabc2cdc5d358a5ce4799cc797c5e214c5e))

- Python `add_elevator_group` takes an optional `machine_room_id`, which must name a Positive Integer Value object (#1023). ([9270394](https://github.com/jscott3201/rusty-bacnet/commit/9270394fed9218eaf5122140e3a624e1a633e1e6))

- **Wire and Rust API:** the application can set Energy_Meter_Ref on an
  Escalator and on a Lift, which gains the optional property. While a
  reference is set, Energy_Meter reads 0.0 (#1036). ([c88f61a](https://github.com/jscott3201/rusty-bacnet/commit/c88f61afece69424171fc35e970b7aefaf6703d8))

- Notification Forwarder Subscribed_Recipients: a `SubscribedRecipients` store with minute
  lifetimes for an application's forwarder, edited by AddListElement and RemoveListElement
  by recipient and process identifier (#1049). ([0bfcfd9](https://github.com/jscott3201/rusty-bacnet/commit/0bfcfd97fa2bb488959e03e9a28f28c0e3a4eda0))

- **Breaking (wire):** the Lift serves nine more optional Table 12-77 rows,
  among them its landing and car calls, door commands, car mode and drive
  status, set by the application and writable while out of service (#1052). ([bfeba23](https://github.com/jscott3201/rusty-bacnet/commit/bfeba23626e30614e99929c6e8a52f0e072286fc))

- **Wire:** a Schedule's Present_Value is writable while Out_Of_Service is
  TRUE, and each written value goes on to the references at
  Priority_For_Writing (#1055). ([122b629](https://github.com/jscott3201/rusty-bacnet/commit/122b6295263ed98daa8f360d5a3c81a1a8b3bcc5))

- **Wire:** a Schedule accepts writes of Weekly_Schedule, Exception_Schedule
  and Effective_Period and applies them at once, and reports
  CONFIGURATION_ERROR while its values mix datatypes (#1057, #1056). ([5e884c5](https://github.com/jscott3201/rusty-bacnet/commit/5e884c58d099ec9a910f1d8df23c985594217f88))

- A running server's application can update a Loop's Controlled_Variable_Value
  through `set_controlled_variable_value_local`, in Rust and Python, with COV
  for property subscribers (#1063). ([f04e5e1](https://github.com/jscott3201/rusty-bacnet/commit/f04e5e1434bcf0f4400ba35cf5b939816d9d986b))

- **Rust API:** the new `CovCounters::untimed_references_oversized`
  counts untimestamped COV-multiple references left out of a report for being
  too large for one notification (#1066). ([3b8fd74](https://github.com/jscott3201/rusty-bacnet/commit/3b8fd74240b9ab8219afe4a72016f211edb5d7d6))

- **Breaking (wire, Rust API):** a running server's application can feed an
  Averaging object samples with `add_averaging_sample_local`, and the object
  takes SubscribeCOVProperty. `AveragingObject::add_sample` returns `Result`
  (#1083). ([417f798](https://github.com/jscott3201/rusty-bacnet/commit/417f7985b8ca6b785cc7ae5a17aa61a88136c03a))

- **Python API:** `BACnetServer.cov_counters()` returns every Rust
  `CovCounters` field in a dict, typed by a new `CovCounters` TypedDict
  (#1084). ([97d084c](https://github.com/jscott3201/rusty-bacnet/commit/97d084cdb9406e0b78d83d8bfce486d95a3cfbe1))

- **Breaking (wire, Rust API):** a Schedule's
  List_Of_Object_Property_References and Priority_For_Writing are
  network-writable, and a target that refuses the schedule's datatype faults
  the Schedule (#1088, #1086). ([7762130](https://github.com/jscott3201/rusty-bacnet/commit/77621307d247d88a91dcb0478a844ffd54bcf880))

- **Breaking (wire, Rust and Python API):** the Averaging object serves
  Window_Interval and Window_Samples and computes its statistics over a
  sliding window instead of every sample since creation (#1092).

- **Breaking (wire, Rust API):** Life Safety Point and Zone gain
  Accepted_Modes, which bounds Mode writes, the Zone gains Tracking_Value, and
  Global Group gains Event_State and Member_Status_Flags (#1092).

- **Breaking (wire, Rust API):** Integer, Positive Integer and Large Analog
  Value gain Units, the Pulse Converter gains its count rows and derives
  Present_Value from Count, and the lighting objects gain their required rows
  (#1092).

- **Rust API:** Python servers take a `cov_policy` dict, and the new
  `CovPolicy::validate` refuses zero caps or budgets and unreachable reserved
  peers, so a Rust server configured with them doesn't start (#1100). ([4535b22](https://github.com/jscott3201/rusty-bacnet/commit/4535b222d513c705c3080ee57297e3cb3d014aa1))

- **Wire:** a Life Safety Point or Zone accepts Tracking_Value and Reliability
  writes while Out_Of_Service is TRUE, and both objects implement
  `set_reliability_internal` (#1108). ([e2ff2d0](https://github.com/jscott3201/rusty-bacnet/commit/e2ff2d0f10d34a79f4bae2804de7ba6696c15f06))

- **Breaking (wire):** The 12 commandable value types serve
  Current_Command_Priority, Integer, Positive Integer and Large Analog Value
  serve a writable COV_Increment that gates their COV notifications, and
  Lighting Output's Default_Fade_Time is writable from 100 to 86,400,000 ms
  (#1111). ([d81bcfa](https://github.com/jscott3201/rusty-bacnet/commit/d81bcfa04d6669bb474a8b0503e83ceecfcccee5))

- **Wire:** AddListElement and RemoveListElement edit a Schedule's
  List_Of_Object_Property_References, and a member naming this server's own
  Device is taken as a local reference (#1121, #1122). ([0c655f6](https://github.com/jscott3201/rusty-bacnet/commit/0c655f61bb445d67d2c99c5b941283a1c13f7878))

- **Breaking (Rust API):** a running server's application can set a Life
  Safety Point or Zone's Present_Value and Tracking_Value through
  `set_present_value_local` and the new `set_tracking_value_local` (#1123). ([27a7ada](https://github.com/jscott3201/rusty-bacnet/commit/27a7ada1b7b75906b0b531948ba24a6d56aa88d2))

- **Wire:** a Staging Target_References element naming this server's own
  Device is accepted as a local reference, as a Schedule's is (#1136). ([2edc489](https://github.com/jscott3201/rusty-bacnet/commit/2edc48980ef4108e590d6235026708d820b414c3))

- `event_notification_counters()` has a count per cause, including
  device_recipient_unbound, recipient_unroutable,
  confirmed_broadcast_recipient, unconfirmed_send_failed, apdu_too_large,
  received_not_forwarded, forwarding_cap_dropped, received_not_logged (#1142,
  #1160, #1196, #1225, #1259, #1346). ([9220fce](https://github.com/jscott3201/rusty-bacnet/commit/9220fce7d794debaa632a6f80ea35939d984015a))

- **Breaking (Rust API):** a running server samples an Averaging object's
  Object_Property_Reference itself, once per Window_Interval / Window_Samples
  seconds; application samples still count (#1144). ([37db5e0](https://github.com/jscott3201/rusty-bacnet/commit/37db5e075083766a4d738ecd200181a29dfb16d6))

- **Wire:** Access Door serves Alarm_Values, Fault_Values and Masked_Alarm_Values and
  reports CHANGE_OF_STATE on Door_Alarm_State, with fault values as
  MULTI_STATE_FAULT, to its Notification Class recipients (#1149). ([a81304f](https://github.com/jscott3201/rusty-bacnet/commit/a81304f82c9a7d51a0d8b8f5d325ba698d6f5e33))

- **Breaking (wire):** writing a Command object's Present_Value runs the
  Action list it selects through the local write path, tracking In_Process and
  All_Writes_Successful; a number past the Action size is refused (#1150). ([c6decbd](https://github.com/jscott3201/rusty-bacnet/commit/c6decbd5edd9034f52595a66754607e4ef730883))

- **Channel object (wire):** Channel (type 53) is back, with its three arrays,
  Last_Priority and Write_Status. A running server passes each Present_Value
  write to the local members, coerced per Table 12-63, at the written priority
  (#1151). ([36d8b72](https://github.com/jscott3201/rusty-bacnet/commit/36d8b7227baafbc1629420e642d16c248aeefe8c))

- **WriteGroup (wire):** the server executes inbound WriteGroup on its Channels
  and declares it, Channels serve Allow_Group_Delay_Inhibit, and
  `BACnetClient::write_group` (Python too) sends to a device or a broadcast
  (#1151). ([50273a5](https://github.com/jscott3201/rusty-bacnet/commit/50273a5236cb5ed52f9d4354ced13f80e94f6fbf))

- **Router control receiver (#1175):**
  `RouterOptions::network_control_receiver` adds a `ReceivedNetworkControl`
  receiver for rejects addressed to the router itself, which still update the
  routing table and are no longer relayed. ([5c1afb3](https://github.com/jscott3201/rusty-bacnet/commit/5c1afb3f1dc2e9a65b25866709c67799f0f34046))

- Python `add_command` takes keyword-only `action` (lists of `ActionCommand` mappings) and `action_text`, so a Python server's Command runs its lists (#1179). ([4c20f13](https://github.com/jscott3201/rusty-bacnet/commit/4c20f135e523b39e53e1dba60f6181545998a259))

- **Breaking (wire):** A Command action naming another device is written there as a confirmed WriteProperty, addressed from the server's device bindings (#1180). ([2a8495a](https://github.com/jscott3201/rusty-bacnet/commit/2a8495a32cb03363e7f8712697e215ee526d2f7e))

- **Breaking (wire):** Trend Log Multiple objects are polled, one value per
  member in each record, and Log_Buffer serves each record framed as
  BACnetLogMultipleRecord (#1203). ([eb86197](https://github.com/jscott3201/rusty-bacnet/commit/eb8619781f2917baa381a61d65fd671dc76bf987))

- `SessionConfig::read_work_limit` and the endpoint builders' `read_work_limit`
  set the shared endpoint's ReadProperty work limit, which a Group's
  Present_Value read is charged to (default 256) (#1215). ([7ad513c](https://github.com/jscott3201/rusty-bacnet/commit/7ad513c5e8ca1dac9df0c386bc7a6a4e1ba5d047))

- **Breaking (wire):** The Notification Forwarder (type 51) returns and forwards received and local event
  notifications to its Recipient_List and Subscribed_Recipients, which can persist across restarts; the
  server now executes ConfirmedEventNotification and UnconfirmedEventNotification (#1225). ([fafc1dd](https://github.com/jscott3201/rusty-bacnet/commit/fafc1ddf07b6f4171f219274d1e2b5ae5c08c529))

- **Breaking (wire):** Lighting Output serves a writable COV_Increment that gates its COV notifications (#1227). ([0d45e79](https://github.com/jscott3201/rusty-bacnet/commit/0d45e792eb1df42ea8bc5bdd71678ed7339c358c))

- **Python API:** `add_trend_log_multiple` takes the members, Log_Interval,
  Logging_Type, Start_Time / Stop_Time window and alignment as keyword
  arguments, so a Python server can run a polled or triggered log (#1235). ([72c1770](https://github.com/jscott3201/rusty-bacnet/commit/72c17700434f51678eab44474bc41bbbe4e5f7e6))

- **Wire:** Trend Log Multiple serves Start_Time, Stop_Time, Align_Intervals,
  Interval_Offset and Trigger, and the server logs inside that window, at
  clock-aligned times and once per Trigger (#1235). ([72c1770](https://github.com/jscott3201/rusty-bacnet/commit/72c17700434f51678eab44474bc41bbbe4e5f7e6))

- **Wire:** Audit Log Buffer_Size takes writes while logging is off, keeping the
  newest records that fit, and `BACnetServer::purge_audit_log` (also in Python)
  lets the application purge a log, leaving a BUFFER_PURGED record (#1238). ([3acf048](https://github.com/jscott3201/rusty-bacnet/commit/3acf0488d3bf760ad00eaefca008d73c857e4c43))

- **Tracked router control receiver (#1242):**
  `RouterOptions::network_control_receiver_with_admission` returns the
  router's network-control receiver as an `AdmissionReceiver`, whose counters
  report its queue depth, high-water mark and drops. ([85f3d2e](https://github.com/jscott3201/rusty-bacnet/commit/85f3d2e24ad1951ff442a8d3ff057956bea3e3a9))

- **Loopback unicast destinations (#1243):**
  `LoopbackTransport::record_unicast_destinations` reports the MAC each
  unicast was sent to, in the order the peer receives the frames, so tests
  can check where a unicast went. ([85f3d2e](https://github.com/jscott3201/rusty-bacnet/commit/85f3d2e24ad1951ff442a8d3ff057956bea3e3a9))

- Python `BipEndpoint`, `ScEndpoint` and `MstpEndpoint` take a keyword-only
  `read_work_limit` (default 256, zero refused) and gain `add_group` (#1250). ([53f39c1](https://github.com/jscott3201/rusty-bacnet/commit/53f39c1cc1d4ac511cd8227cc80ddc7687d67c48))

- **Rust API:** A Notification Forwarder built with persistence keeps a written
  Recipient_List across a restart too, and it wins over configured destinations (#1256). ([1d3eb21](https://github.com/jscott3201/rusty-bacnet/commit/1d3eb211c7700a20b59320ddf968c4fe8c269744))

- Python `add_notification_forwarder` takes keyword-only `recipients` and `port_filter`
  to seed Recipient_List and Port_Filter, and `BACnetServer.forwarder_save_counters()`
  reports failed Subscribed_Recipients saves (#1260). ([6ef5fe4](https://github.com/jscott3201/rusty-bacnet/commit/6ef5fe452a3a29dbee8759b69ddc7238cfdc9187))

- **Python API:** `BACnetServer.add_channel` registers a Channel with its
  members, execution delays, control groups and Allow_Group_Delay_Inhibit.
  Its members, and `add_trend_log_multiple`'s, are `(object, property)`
  tuples or mappings (#1262). ([c59f965](https://github.com/jscott3201/rusty-bacnet/commit/c59f9656afd3e21e794daa1eca040cfa9428a19d))

- **Wire:** A Channel member in another device is written there as a confirmed WriteProperty, and the Channel serves Reliability, naming why a FAILED distribution failed (#1264). ([0863c0f](https://github.com/jscott3201/rusty-bacnet/commit/0863c0f590582684016b70b3ff1f89442509b2a5))

- `bacnet read-range` decodes Trend Log, Event Log, Trend Log Multiple and
  Audit Log records instead of printing hex; its JSON for a log buffer lists
  them under `records` instead of `items` (#1274). ([ea05d58](https://github.com/jscott3201/rusty-bacnet/commit/ea05d5890885085fd54f7e3e3f6a0d186434fda2))

- A server with a valid Device clock records the device's own event notifications
  in each Event Log, except BUFFER_READY reports on an Event Log's buffer and
  reports from a local Event Enrollment that watches a local Event Log (#1275). ([019a20b](https://github.com/jscott3201/rusty-bacnet/commit/019a20b6688f7095c9526549da7dcbb8d07c6e44))

- **Wire and Rust API:** Access Point serves Authentication_Status, DISABLED
  while out of service, and Access_Event_Credential, which `set_access_event`
  takes with each event (#1284). ([9cd82bc](https://github.com/jscott3201/rusty-bacnet/commit/9cd82bc9c4126d5fa0953099a9fa5fdd898e52c2))

- **Wire:** Access Zone serves Occupancy_State, Event_State and its
  occupancy-counting properties, with Adjust_Value writable (#1284). ([9cd82bc](https://github.com/jscott3201/rusty-bacnet/commit/9cd82bc9c4126d5fa0953099a9fa5fdd898e52c2))

- Python `BACnetServer.add_group` takes `members`, checked as the endpoint `add_group`
  checks them, so a Python server serves a Group's Present_Value (#1286). ([6ef5fe4](https://github.com/jscott3201/rusty-bacnet/commit/6ef5fe452a3a29dbee8759b69ddc7238cfdc9187))

- **Loopback data attributes (#1289):** `LoopbackTransport::carry_data_attributes`
  hands the peer the data attributes each frame is sent with, so tests can
  check the attributes a router sends back. By default they are still dropped. ([a48c931](https://github.com/jscott3201/rusty-bacnet/commit/a48c931e7e209e30959d1ddb8ac88586a2db9a95))

- Python `BACnetServer` takes a keyword-only `time_sync_policy` dict for the time-sync
  allowlist, step cap, rate limits and coalescing, and
  [time sync policy](docs/time-sync-policy.md) documents the policy (#1292). ([6ef5fe4](https://github.com/jscott3201/rusty-bacnet/commit/6ef5fe452a3a29dbee8759b69ddc7238cfdc9187))

- **Rust API:** `BACnetServer::write_local_encoded` writes a local property from
  its encoded value through the WriteProperty handler's decoding (#1296). ([ce572cf](https://github.com/jscott3201/rusty-bacnet/commit/ce572cf812e35750d255bfc885eb5ebdfe364548))

- `NetworkLayer::local_network_number` is a lock-free handle to the local network number for
  stacks and adapters built directly on `NetworkLayer`; the full server and client fill their own
  layers internally (#1298). ([5e66d84](https://github.com/jscott3201/rusty-bacnet/commit/5e66d84a1278aa6fd8795cc2487653d77334fad7))

- **Wire:** Access Zone reports CHANGE_OF_STATE on Occupancy_State, with its
  event properties and Alarm_Values, to its Notification Class recipients
  (#1305). ([bbf4acb](https://github.com/jscott3201/rusty-bacnet/commit/bbf4acb25aa4100df6fd1c289ff56cc71473376a))

- **Wire:** Access Point serves Active_Authentication_Policy,
  Number_Of_Authentication_Policies, Authorization_Mode and
  Priority_For_Writing; clients can write the policy in effect and the mode
  (#1307). ([ecc1af4](https://github.com/jscott3201/rusty-bacnet/commit/ecc1af46d41a04c886f5909d7866b62e0592e7d8))

- **Python API:** an `ActionCommand` for `add_command` accepts
  `write_successful` and ignores it, so the mappings a read of Action returns
  can be given back (#1310). ([e04ef28](https://github.com/jscott3201/rusty-bacnet/commit/e04ef2883cafe4f8b1a3958a3b5395928723a183))

- A Notification Class can keep a written Recipient_List across a restart:
  `NotificationClass::with_persistence` with `FileNotificationClassPersistence`, or
  `storage_path` on Python's `add_notification_class` (#1315). ([aaba646](https://github.com/jscott3201/rusty-bacnet/commit/aaba646b05bd788928cf10603482511899d5ba4a))

- **Rust and Python API:** Access Rights serves positive and negative access
  rules, set with `set_positive_access_rules`, `set_negative_access_rules` or
  `add_access_rights`, read in Python as `AccessRule` mappings. **Breaking
  (Rust API):** `BACnetAccessRule` takes its Clause 21 shape (#1316, #1344). ([2323bf7](https://github.com/jscott3201/rusty-bacnet/commit/2323bf7cfd07a888ebf64c1272cec84657c1e642))

- **Wire:** Target Audit reporting records each Channel write of an inbound
  WriteGroup as a WRITE of its Present_Value from the requester. A Channel's
  Present_Value counts as commandable, so its WriteProperty records carry the
  priority and drop at priorities Audit_Priority_Filter disables (#1318). ([cbe62f3](https://github.com/jscott3201/rusty-bacnet/commit/cbe62f311b478671b7cafadb789affb2fbf238c9))

- **Wire:** A Command action or Channel member in a device with no fresh binding sends one Who-Is for it, globally or where its last I-Am came from, and waits the APDU timeout for the I-Am; at most one a minute per device, none while DCC restricts initiation (#1322). ([83cfadb](https://github.com/jscott3201/rusty-bacnet/commit/83cfadb9ff9e434be27946a29b590c2ebaa39c4b))

- **Wire, Python API:** every object that reports intrinsically serves
  Event_Message_Texts_Config, whose texts replace the server's Message Text,
  and Event_Algorithm_Inhibit with its _Ref, which suspends the event
  algorithm but not fault reporting and can follow a local property (#1329). ([d63feb9](https://github.com/jscott3201/rusty-bacnet/commit/d63feb908613f0550d858a19bef70a25ebc67796))

- **Wire and Rust API:** Access Rights takes WriteProperty and
  WritePropertyMultiple of Positive_Access_Rules and Negative_Access_Rules,
  whole, by index or resized at index 0, with the setters' checks; either
  array holds at most `MAX_ACCESS_RULES` (1024) rules (#1330). ([997733d](https://github.com/jscott3201/rusty-bacnet/commit/997733d52de1a6ef06d3698c179b2115044b9bc4))

- **Wire, Rust and Python API:** Access Rights serves its required Enable row
  (property 133), TRUE by default and writable, set with `set_enable` or the
  `add_access_rights` `enable` keyword in Python (#1332). ([997733d](https://github.com/jscott3201/rusty-bacnet/commit/997733d52de1a6ef06d3698c179b2115044b9bc4))

- **Wire, Rust and Python API:** an Event Log can record the event
  notifications the server receives, opted in with
  `EventLogObject::set_log_received_notifications` or
  `add_event_log(log_received_notifications=True)`; each source is held to
  5 records a second (#1346). ([d3529d5](https://github.com/jscott3201/rusty-bacnet/commit/d3529d5154f715f4d99a641555949bd17a0b6b58))

- **Wire:** Event Log, Trend Log and Trend Log Multiple serve the intrinsic
  reporting rows and send a BUFFER_READY notification to their Notification
  Class each time Notification_Threshold more records are collected; no Event
  Log records a report on an Event Log's buffer (#1347). ([d3529d5](https://github.com/jscott3201/rusty-bacnet/commit/d3529d5154f715f4d99a641555949bd17a0b6b58))

- **Wire:** Trend Log and Event Log serve writable Start_Time and Stop_Time
  and keep records only inside that window, logging each opening and
  closing; the server's poller now looks at Event Log windows too (#1353). ([1be8248](https://github.com/jscott3201/rusty-bacnet/commit/1be824832f0d675a17f3f3cf9846eb230287c57b))

- **Wire:** Trend Log serves Trigger, Align_Intervals and Interval_Offset and
  takes Logging_Type writes, so the server polls it at clock-aligned times or
  once per Trigger (#1354). ([1be8248](https://github.com/jscott3201/rusty-bacnet/commit/1be824832f0d675a17f3f3cf9846eb230287c57b))

- **Python API:** `BACnetClient.write_group` takes a `PropertyValue` as a
  change-list value and encodes it, beside encoded `bytes` or `bytearray`; a
  list of ints is no longer taken as the encoded octets (#1359). ([cbe62f3](https://github.com/jscott3201/rusty-bacnet/commit/cbe62f311b478671b7cafadb789affb2fbf238c9))

- **Python API:** `add_notification_class` takes keyword-only `recipients=`
  to seed a Notification Class's Recipient_List, with the checks and
  saved-list precedence of `add_notification_forwarder`'s (#1364). ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Wire:** an event notification to a Device recipient with no fresh binding sends one Who-Is and
  waits, behind the ones already waiting for that device, up to the APDU timeout (a minute at most)
  for the I-Am; at most 1,024 wait, none under DCC, a silent device counted once (#1368). ([aef70c4](https://github.com/jscott3201/rusty-bacnet/commit/aef70c43149af99d5c3dcc3d36d5ccc3313f7eb1))

- **Wire:** the Device's Device_Address_Binding lists the server's configured bindings and I-Am
  observations under ten minutes old, on every read path; a value the application stored is replaced
  by that list, and by an empty one on the endpoint (#1369). ([aef70c4](https://github.com/jscott3201/rusty-bacnet/commit/aef70c43149af99d5c3dcc3d36d5ccc3313f7eb1))

- **Python API:** a read of the Device's Device_Address_Binding comes back typed, one
  `"address_binding"` element per binding: a mapping of `device_identifier`, `network_number` and
  `mac_address` (#1369). ([aef70c4](https://github.com/jscott3201/rusty-bacnet/commit/aef70c43149af99d5c3dcc3d36d5ccc3313f7eb1))

- **Rust API:** `bacnet_encoding::constructed::tagged` adds `decode_app_fixed`,
  `decode_app_object_id` and `next_is_application` (#1374, #1375). ([d682790](https://github.com/jscott3201/rusty-bacnet/commit/d68279070d0a21da717d84f10db7854b59a2f10b))

- **Rust API:** `constructed::tagged` makes `expect_opening`, `expect_closing`,
  `decode_optional_ctx`, `decode_ctx_character_string`,
  `decode_ctx_bit_string`, `decode_ctx_octet_string`, `decode_app_bit_string`
  and `decode_app_character_string` public (#1374). ([d682790](https://github.com/jscott3201/rusty-bacnet/commit/d68279070d0a21da717d84f10db7854b59a2f10b))

- **Breaking (wire):** Lighting Output carries out its lighting commands:
  fades and ramps move Tracking_Value, steps and STOP act on the priority
  array, and the warn commands (also Present_Value -1.0 to -3.0) act at once,
  or blink and hold for Egress_Time when Blink_Warn_Enable is TRUE (#1384). ([b9ad662](https://github.com/jscott3201/rusty-bacnet/commit/b9ad6626f88014b09126ec57860110a6667fbbc9))

- **Rust API:** `BACnetColorCommand`, `BACnetXyColor` and `ColorOperation` in
  bacnet-types, their codecs in `bacnet_encoding::constructed`, and
  `set_color_command` and `color_command` on both colour objects (#1386). ([97baf49](https://github.com/jscott3201/rusty-bacnet/commit/97baf4921afafc2ae9018a0dd68706de4e879bcd))

- **Wire:** With target Audit configured, the server reports each DeviceCommunicationControl change
  it carries out, and a timed disable running out, as DEVICE_DISABLE_COMM or DEVICE_ENABLE_COMM
  records (#1387). ([b07dc35](https://github.com/jscott3201/rusty-bacnet/commit/b07dc359cf5d2d0c43317b31462910b7d14e225d))

- Access Rights can keep the rule arrays and Enable that peers write across a restart:
  `AccessRightsObject::with_persistence` with `FileAccessRightsPersistence`, or `storage_path`
  on Python's `add_access_rights` (#1392). ([7b7905b](https://github.com/jscott3201/rusty-bacnet/commit/7b7905ba09cf6b1bb469b0eb11af58b4d2b7a293))

- **Wire, Rust and Python API:** Access Rights serves its optional
  Accompaniment row once the application sets it (`set_accompaniment`, or
  `accompaniment` on `add_access_rights`); peers can write it,
  `with_persistence` keeps what they write, and Python reads it in the
  keyword's form (#1393, #1344). ([b32ee3b](https://github.com/jscott3201/rusty-bacnet/commit/b32ee3bbdf78c47c3cea545d4192261f1f734191))

- **Wire, Rust and Python API:** Access User serves Members and Member_Of;
  `set_credentials`, `set_members` and `set_member_of`, or the matching
  `add_access_user` keywords, fill its three lists, and Python reads them in
  the keywords' forms (#1394, #1344). ([7cd802c](https://github.com/jscott3201/rusty-bacnet/commit/7cd802cb427216243a764e67f1b136e533a931ac))

- **Rust API:** `bacnet_encoding::constructed` adds
  `decode_object_property_reference_at` and `decode_setpoint_reference_at`,
  which decode a reference at an offset and return the offset past it (#1414). ([d54b143](https://github.com/jscott3201/rusty-bacnet/commit/d54b143114dbc71de28731df2362893a34824393))

- **Python API:** `add_access_zone` takes `alarm_values`, the Access Zone's
  starting Alarm_Values, with the checks a write gets, so NORMAL is refused
  (#1421). ([b32ee3b](https://github.com/jscott3201/rusty-bacnet/commit/b32ee3bbdf78c47c3cea545d4192261f1f734191))

- **Wire and Rust API:** CreateObject sets Units on Analog Input and Output,
  which stay read-only to WriteProperty, and Number_Of_States and State_Text
  on the multi-state objects; `pics::ObjectTypeSupport` gains
  `creation_only_properties`, so struct literals need it (#1429). ([fe20bc5](https://github.com/jscott3201/rusty-bacnet/commit/fe20bc58092d5e07ad4d7e6b7796f60696472854))

- **Python API:** the enum classes (`ObjectType`, `EnableDisable`,
  `ErrorCode` and the rest) belong to the `rusty_bacnet` module and support
  `copy.copy`, `copy.deepcopy` and `pickle` (#1456). ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- `CONTRIBUTING.md`, issue forms for bug reports and feature requests, and a
  pull request template explain how to report a problem and propose a change
  on GitHub (#1472). ([78fd518](https://github.com/jscott3201/rusty-bacnet/commit/78fd51855e00cf82c1b14154acfc6014a23c67ce))

- `TransportPort::is_group_destination` and `group_destinations` say whether a
  MAC reaches a group of nodes, such as any B/IP broadcast or multicast
  address at any port or any IPv6 multicast group, beside the link's own
  broadcast MAC (#1479). ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- **Python API:** `ObjectIdentifier`, `PropertyValue` (typed constructed
  reads included) and `BACnetTimeStamp` support `copy.copy`,
  `copy.deepcopy` and `pickle`, and every exported class belongs to the
  `rusty_bacnet` module (#1500). ([17404bb](https://github.com/jscott3201/rusty-bacnet/commit/17404bb55178e00727f2431bc2ccbc44a87599ad))

### Changed

- **Breaking (Rust and Python API):** AuditLogQuery's success filter is the
  three-state `BACnetSuccessFilter`, so failures-only now filters, and the
  start sequence number is an Unsigned64 cursor (#345).

- **Rust and Python API:** a server can run 1 to 64 target Audit Reporters
  that send bounded notifications for inbound writes, list edits, file writes
  and object creation and deletion, plus summaries of dropped records; the
  lowest instance is elected and all share one admission budget (#345, #782).

- **Python API:** `BACnetServer.configure_audit_notification_sink` lets a
  standalone server take Audit notifications into a file-backed Audit Log
  under an explicit policy; see the
  [receiver configuration](docs/python-api.md#inbound-audit-notification-sink)
  (#345).

- **Python API:** a standalone B/IP server binds Device addresses with
  `add_device_binding` and forwards its Audit Log to a parent with
  `configure_audit_log_parent`; see
  [parent forwarding](docs/python-api.md#direct-audit-log-parent-forwarding)
  (#345).

- **Breaking (CLI):** `bacnet --sc` requires `--sc-ca` with explicit site CA
  certificates and no longer loads the system roots; see the
  [CLI migration](docs/CLI.md#transport-variants) (#513).

- **Breaking (Rust API):** `ScHub::start` and its variants take an
  `ScHubTlsConfig` instead of a `TlsAcceptor`, enforcing explicit CA trust,
  client verification and TLS 1.3, and the server-auth-only SC benchmarks are
  retired (#513).

- `ScHubTlsConfig::from_der` builds hub TLS from loaded CA, chain and key DER
  with mandatory client verification and TLS 1.3 only, and Python hub startup
  uses it (#513).

- **Breaking (Rust API):** `TlsWebSocket::connect` and the SC client and
  server builders' `tls_config` take an opaque `ScNodeTlsConfig` built from
  CA, chain and key DER instead of a rustls `ClientConfig` (#513).

- The mTLS benchmark hub launcher and the CLI and server SC test fixtures
  build their TLS through `ScHubTlsConfig` (#513).

- **Breaking (Python API):** `BACnetClient` and `BACnetServer` with
  `transport="sc"` require `sc_ca_cert`, `sc_client_cert` and `sc_client_key`,
  with no fallback to the system roots; see
  [SC configuration](docs/python-api.md#bacnetsc-secure-connect) (#513).

- **Breaking (Python API):** `ScHub` requires an explicit `ca_cert` and always
  verifies clients over TLS 1.3, with no one-way TLS default; see
  [ScHub](docs/python-api.md#schub) (#513).

- **Breaking (CLI):** `bacnet-sc-hub` requires `--ca`, `--cert` and `--key`,
  and `bacnet-device --transport=sc` its SC credentials and identity, for
  mutual TLS 1.3; see the [Docker recipe](examples/docker/README.md) (#513).

- **Breaking (Rust and Python API):** every SC hub startup API requires a
  nonzero hosting device UUID (`device_uuid` in Python, `--device-uuid` for
  `bacnet-sc-hub`) and refuses reserved hub VMACs (#517).

- **Breaking (Rust API):** `ScTransport::start` requires a nonzero UUID set
  with `with_device_uuid`, and refuses reserved local VMACs (#517).

- **Wire:** an initiating SC node silently discards a Connect-Accept with an
  all-zero peer UUID, so it can't complete the handshake (#517).

- **Wire:** an SC hub refuses a Connect-Request carrying an all-zero Device
  UUID before it registers the peer (#517).

- **Breaking (Rust and Python API):** `ScServerBuilder` requires
  `device_uuid`, and Python SC clients and servers the keyword
  `sc_device_uuid`; provision one UUID per device and keep it for life (#517).

- **Wire:** an accepting SC hub silently discards an unsolicited
  Connect-Accept or Disconnect-ACK without touching its state (#519).

- **Wire:** an SC Connect-Request or Connect-Accept that advertises a zero
  Max-BVLC or Max-NPDU is refused (#519).

- **Wire:** SC nodes and hubs discard an empty Encapsulated-NPDU, answering an
  eligible unicast with a NAK (#519).

- **Wire:** an SC hub relays registered unicast Address-Resolution requests
  and ACKs between nodes (#519).

- **Wire:** an SC hub relays registered, addressed messages of unknown
  function and returns their results (#519).

- **Wire:** an unsupported Must Understand option on a received SC NPDU no
  longer refreshes node activity or clears a pending heartbeat (#519).

- **Wire:** an established SC node rejects a BVLC function it doesn't know
  before refreshing activity, with a NAK for an eligible unicast (#519).

- An SC node's rejection NAKs must go out within the remaining heartbeat
  budget; a node that misses it retires the socket and recovers only through a
  fresh connection (#519).

- The server bounds request admission with configurable global and per-peer
  quotas, keeps a reserve for DCC ENABLE, and joins its request work on stop;
  see the
  [acceptance matrix](docs/request-admission.md#bounded-acceptance-and-evidence)
  (#521).

- **Rust and Python API:** an optional, default-off token bucket limits DCC
  DISABLE_INITIATION requests per server (`dcc_disable_rate_limit`); see
  [DCC policy](docs/dcc-policy.md) (#522).

- **Rust and Python API:** with `RequirePassword`, DCC can also be limited to
  an exact list of claimed source addresses, which remain spoofable; see
  [DCC policy](docs/dcc-policy.md) (#522).

- **Breaking (Rust API):** a custom `TransportPort` must provide
  `local_receive_apdu_capacity()`, `max_apdu_length()` is renamed
  `egress_apdu_limit()` with no alias, and `ReceivedNpdu` gains `provenance`
  and `direct_response` (#693). ([df016bb](https://github.com/jscott3201/rusty-bacnet/commit/df016bb551d99c88bd42b96cb6bca8ec75651045))

- `MstpTransport::diagnostics()` exposes redacted, counts-only MS/TP host
  diagnostics, and a [bench method](docs/mstp-qualification.md) describes how
  to qualify a host (#707, #502).

- Direct B/IP endpoint client sessions can report their ReadProperty requests
  as bounded source audit records to the Device's recipient; see
  [endpoint source READ](docs/rust-api.md#bounded-endpoint-source-read-reporting)
  (#727, #345).

- **Rust API:** endpoint source auditing sends to the built-in Device's
  recipient; see the [Device audit recipient](docs/device-audit-recipient.md)
  contract (#728).

- **Rust and Python API:** the Audit recipient lives on the built-in Device,
  and Python sets it with `configure_audit_recipient` (#728).

- Endpoint source READ audit records lost to resource exhaustion are
  summarized in one bounded AUDITING_FAILURE count (#732, #345).

- **Wire:** an SC node without a live matching direct listener answers
  Address-Resolution with a NAK instead of a URI ACK (#733).

- **Breaking (Rust API):** custom objects report intrinsic events through one
  proposal and commit contract, and
  `intrinsic_reporting_requires_atomic_commit` and the
  `impl_intrinsic_reporting!` macro are gone (#746).

- Tests run with cargo-nextest 0.9.145 or later in CI, the release gate and
  `scripts/ci/local-macos.sh`, plus `cargo test --doc` for doctests (#751). ([56249e6](https://github.com/jscott3201/rusty-bacnet/commit/56249e66f6c29e8e41031f7f2defc2db55827219))

- **Breaking (Rust API):** `BACnetObject::apply_life_safety_operation` returns
  a `LifeSafetyOperationOutcome` listing the exact property changes, replacing
  the `_detailed` hook (#752).

- **Rust and Python API:** SC hub admission sees the current UUID and VMAC
  registration, and Python can opt into
  `admission_policy="deny_uuid_replacement"` to keep an incumbent (#767,
  #476).

- **Python API:** `BACnetServer` takes `mutation_policy="deny_all"` to refuse
  the ten network mutation services while reads and trusted local writes still
  work; the default stays permissive (#768).

- **Rust and Python API:** `ScHubProbePolicy` configures the SC hub's probe
  timing on a monotonic clock, and Python exposes the hub's relay send budget
  and broadcast-rate policy (#769, #476).

- **Rust and Python API:** SC hub status adds per-start counters of its
  replacement and removal decisions (#770, #476).

- **Rust and Python API:** the endpoint client sends ReadRange through the
  shared request path and records one source Audit READ per attempt; ReadRange
  request encoding returns `Result` (#771, #345).

- **Rust and Python API:** one SC hub relay send budget, five seconds unless
  configured, bounds every unicast, broadcast and forwarded-result relay, so a
  blocked destination no longer holds up the source's reader (#762, #774,
  #476).

- **Wire:** an SC hub answers a peer's WebSocket Close with its own Close and
  reclaims the peer's slot (#776).

- Standalone and endpoint clients share ReadProperty ACK validation, so an ACK
  for another object, property or index is a decoding error (#784, #345).

- **Wire:** a ReadPropertyMultiple response includes a property array index
  only for declared arrays (#789).

- **Rust and Python API:** WritePropertyMultiple request encoding returns
  `Result` and validates every write first, refusing empty lists, special
  property selectors and invalid priorities (#793).

- **Rust and Python API:** AddListElement and RemoveListElement request
  encoding returns `Result` and refuses index zero, empty elements and
  malformed framing (#798).

- **Breaking (Rust API):** the `BACnetClient::builder()` and
  `BACnetServer::builder()` aliases are gone (#873).

- **Breaking (Rust API):** `bacnet_server::schedule::tick_schedules` drops its
  unused UTC-offset argument (#889).

- **Breaking (Rust API):** `AnyTransport::Bip` holds a `Box<BipTransport>`,
  like `Sc`, and `From<BipTransport>` still converts (#902).

- `clippy::print_stdout` and `clippy::print_stderr` are denied across the
  workspace, and library crates report through `tracing` (#902).

- Every public item is documented and `missing_docs` is denied. CI treats
  clippy and rustdoc warnings as errors for every feature set, the PyO3 crate
  and each published crate on its own (#902, #906).

- **Breaking (Rust API):** long parameter lists become structs, such as
  `CovPropertySubscription` for `subscribe_cov_property` and `RoutedTarget`
  for routed sends (#902).

- **Rust API:** `ClientRoleHandle::write_property` takes a
  `WritePropertyRequest`, and `NetworkLayer::send_response_apdu_on_issuance`
  an `IssuedApdu` (#902).

- CI builds the Python bindings with maturin and runs their test suite on
  every PR, and Cargo Deny checks their dependencies (#903). ([e1ca5a6](https://github.com/jscott3201/rusty-bacnet/commit/e1ca5a6096f132509ae9acde8d4e9dd2d43b5ad4))

- **Breaking (Rust and Python API):** alarm and event service types use the
  `bacnet-types` enumerations and bit strings instead of raw integers, with
  the wire encoding unchanged (#914). ([ca35afc](https://github.com/jscott3201/rusty-bacnet/commit/ca35afcde79727fce0176fc562e280d93134904d))

- **Breaking (Rust API):** the `bacnet-objects` event detectors and enrollment
  objects hold typed transitions, notify types and reliabilities, and the
  duplicate `bacnet_objects::event::LimitEnable` is gone (#914). ([ca35afc](https://github.com/jscott3201/rusty-bacnet/commit/ca35afcde79727fce0176fc562e280d93134904d))

- Optional dependencies are no longer published as implicit features; enable
  the documented `ipv6`, `sc-tls`, `serial`, `serial-gpio`, `ethernet`,
  `pcap`, `std` or `serde` feature instead (#917). ([85e402c](https://github.com/jscott3201/rusty-bacnet/commit/85e402ce205890a92963e104fa97e1c33a1026bd))

- The workspace no longer turns on pyo3's `extension-module` feature, so
  `cargo nextest run -p rusty-bacnet` links libpython and runs the crate's
  tests (#919). ([e40ea24](https://github.com/jscott3201/rusty-bacnet/commit/e40ea249a7b608478eab2a325c20f9a31a13be4e))

- **Breaking (Rust and Python API):** GetEnrollmentSummary's acknowledgment
  filter is an `AcknowledgmentFilter`, and every stored Event_State and
  Event_Type is typed (#930). ([e67cd5c](https://github.com/jscott3201/rusty-bacnet/commit/e67cd5cbd2c3dded0df9b19edf9de241e6d192c4))

- **Breaking (Rust API):** Notification Class recipients use typed bit strings
  (`DaysOfWeek`, `EventTransitionBits`), and `pack_octet` and `unpack_octet`
  are no longer public (#930). ([e67cd5c](https://github.com/jscott3201/rusty-bacnet/commit/e67cd5cbd2c3dded0df9b19edf9de241e6d192c4))

- **Breaking (Rust API):** objects store Reliability as a typed enumeration,
  and Life Safety Point and Zone, the access-control objects and Elevator
  Group store their enumerated fields typed too; the wire values and the
  Python API are unchanged (#932). ([339a02a](https://github.com/jscott3201/rusty-bacnet/commit/339a02a068df641867ccee41f6076fa6ce7fea7e))

- The pinned development, CI and release toolchain moves to Rust 1.99.0; the
  MSRV stays 1.93 (#936). ([d9b0f91](https://github.com/jscott3201/rusty-bacnet/commit/d9b0f9125b939c61ea4e0f6749ab7e17f51d19ab))

- Releases are built on GitHub's runners, each wheel and CLI binary natively
  on its own platform (Linux x86_64 and arm64, macOS Apple Silicon and Intel,
  Windows), and run there before anything is published (#943, #944, #1472). ([dfc317a](https://github.com/jscott3201/rusty-bacnet/commit/dfc317a071f8abfa8a0182874cc65fd830a8e211))

- `tokio-tungstenite` is built without TLS features, so nothing loads the
  system root certificates and the native-certs crates leave the lockfile
  (#944). ([dfc317a](https://github.com/jscott3201/rusty-bacnet/commit/dfc317a071f8abfa8a0182874cc65fd830a8e211))

- The test suites, clippy and rustdoc also run natively on macOS and Windows,
  in parallel test and lint jobs on GitHub-hosted runners (#950). ([7abb5e4](https://github.com/jscott3201/rusty-bacnet/commit/7abb5e451793bca30c923e2244e6bba93efea336))

- **Breaking (Rust API):** `Error` gains `UnsupportedTransport`, the client
  BBMD helpers work on any transport that implements `AsBip`, and
  `ScTransport::connection()` and `MstpTransport::node_state()` are private
  (#956). ([5e9e676](https://github.com/jscott3201/rusty-bacnet/commit/5e9e6763b3224ff7dfc2e19ad7a6c9a132587a3a))

- The workspace uses Cargo's `resolver = "3"`, so lock file updates prefer
  dependency versions that support the MSRV (#961). ([6d866b6](https://github.com/jscott3201/rusty-bacnet/commit/6d866b683f92c23fd06a0ed0d2ab4e5e17f4ccc8))

- CI's per-crate default-features check also covers the Windows and macOS
  targets, and the native Windows job stops the Compatibility Appraiser that
  upset test timing (#981, #1003). ([b28c16f](https://github.com/jscott3201/rusty-bacnet/commit/b28c16ffba4dc8a8672c1a31ccda0c8f15869c02))

- A COV-multiple context keeps up to about four notifications of timestamped
  changes, under a memory ceiling; overflow drops the oldest, never a
  reference's newest or partly sent one, counted in
  `CovCounters::timed_changes_dropped` and warned once per cause (#1039,
  #1163, #1197, #1287, #1357). ([a8450ee](https://github.com/jscott3201/rusty-bacnet/commit/a8450ee759a7ba9bcbec6826fff63596c9dc8cdf))

- Test-only: the endpoint Device-write, benchmark hub-restart and BBMD tests
  no longer fail when another socket takes their port (#1068). ([6bf9a0e](https://github.com/jscott3201/rusty-bacnet/commit/6bf9a0ecbcf51dd36d30fe8b39927c9903df83d3))

- Test-only: the BBMD restart and port-release tests rerun on fresh ports when
  another socket takes the port between the stop and the bind (#1070). ([499dd0c](https://github.com/jscott3201/rusty-bacnet/commit/499dd0c803eb2e075ad7c2ecf429153cf35297c8))

- Test-only: the SC hub shutdown and B/IP restart tests rerun on fresh ports
  the same way, through test-only `port_ownership` helpers shared in
  `bacnet-transport` (#1070, #1095). ([499dd0c](https://github.com/jscott3201/rusty-bacnet/commit/499dd0c803eb2e075ad7c2ecf429153cf35297c8))

- The Python and Rust API docs give Network Port snapshots, the SC heartbeat
  and identity settings and the Audit Reporter their own headings (#1071). ([499dd0c](https://github.com/jscott3201/rusty-bacnet/commit/499dd0c803eb2e075ad7c2ecf429153cf35297c8))

- **Breaking (wire, Rust API):** Access Credential and Access Door serve every
  required row of their tables. Credential_Status is derived from
  Reason_For_Disable, a door command outside the four BACnetDoorValue values
  is refused, and a pulse unlock relinquishes after its pulse time (#1073,
  #979). ([42e4528](https://github.com/jscott3201/rusty-bacnet/commit/42e45288181d8fa383c5b41fce6de387bdb034a1))

- The running server's Device read view forwards every read-only
  `BACnetObject` query to the object it wraps, and a test fails when one isn't
  forwarded (#1076). ([436dd01](https://github.com/jscott3201/rusty-bacnet/commit/436dd01dd5ff577d5cccf2a15e0ca91639969a94))

- **Breaking (wire):** Audit Log serves Log_Buffer through ReadRange by position, sequence or time, and
  ReadProperty answers it with READ_ACCESS_DENIED. ReadRange references and First Sequence Number are
  `u64` (#1092). ([e49a6f3](https://github.com/jscott3201/rusty-bacnet/commit/e49a6f35072009ee10dd2333a262039b41225c02))

- **Breaking (Python API):** a transport I/O failure raises
  `BacnetTransportError`, a subclass of both `BacnetError` and `OSError` that
  carries `errno`, and the message loses its `transport error:` prefix
  (#1120). ([b9ae0e2](https://github.com/jscott3201/rusty-bacnet/commit/b9ae0e2ef2b38111252b47cddaf550d520522de2))

- **Wire and Rust API:** Access Door keeps Door_Alarm_State to NORMAL and its
  alarm and fault values, outside its masked values, refusing other states from
  the application and from clients (#1149). ([a81304f](https://github.com/jscott3201/rusty-bacnet/commit/a81304f82c9a7d51a0d8b8f5d325ba698d6f5e33))

- **DCC source restriction entry length:** `DccSourceRestriction` and the
  Python `dcc_source_restriction` keyword refuse an entry longer than
  `BACnetAddress::MAX_MAC_LEN` (18 octets), which could never match a source
  (#1157). ([0696eb8](https://github.com/jscott3201/rusty-bacnet/commit/0696eb861cae65a1c4a855bdb0ddbcc4c48aa3fb))

- Reading a Group's Present_Value charges every member row to the request's
  ReadPropertyMultiple work limit, so a request that would pass it is aborted
  with OUT_OF_RESOURCES (#1172). ([15a787f](https://github.com/jscott3201/rusty-bacnet/commit/15a787fb2dc82d3811ce3d6a8070304a7f444d36))

- Changelog entries are one or two high-level sentences naming the issue,
  which `changelog.py check` enforces, and `assemble` links each entry to its
  GitHub commit (#1188). ([942c31f](https://github.com/jscott3201/rusty-bacnet/commit/942c31fe510373660b07bdf1b0f40ceb216ae4d4))

- **Rust and Python API:** `CovPolicy` and the Python `cov_policy` keyword
  refuse a reserved peer or recipient MAC longer than 18 octets, which could
  never match a subscriber (#1199). ([981024a](https://github.com/jscott3201/rusty-bacnet/commit/981024a31d3bcb15fcb5d84136a4fb4c2d16e546))

- With several Devices in the database, Audit Reporters, Audit Log receipt and
  forwarding, endpoint Device writes and the standalone PICS treat the lowest
  as this device, as wildcard reads already do, where they used to refuse or
  pick any one ([details](docs/rust-api.md#databases-with-several-devices), #1204). ([0897982](https://github.com/jscott3201/rusty-bacnet/commit/089798289ead647e370c92189dd2af85a1f05c18))

- **Breaking (wire, Rust API):** Trend Log Multiple refuses COV logging, over
  the wire and through `set_logging_type`, which returns `Result`; both trend
  objects' `set_logging_type` take a `LoggingType`, and a log with a
  proprietary Logging_Type is no longer polled (#1235). ([72c1770](https://github.com/jscott3201/rusty-bacnet/commit/72c17700434f51678eab44474bc41bbbe4e5f7e6))

- **Wire:** an Audit Log Log_Enable write whose commit fails is refused with a
  device error instead of a generic one, as Buffer_Size writes are (#1238). ([3acf048](https://github.com/jscott3201/rusty-bacnet/commit/3acf0488d3bf760ad00eaefca008d73c857e4c43))

- **Rust and Python API:** `AuditLogObject::new` and Python `add_audit_log` reopen
  a log with the Buffer_Size it stored, which a peer may have written, instead of
  failing when `buffer_size` differs; a warning names both sizes (#1238). ([3acf048](https://github.com/jscott3201/rusty-bacnet/commit/3acf0488d3bf760ad00eaefca008d73c857e4c43))

- **Rust API:** `GroupObject::add_member` returns a `GroupMemberRefusal`
  naming the rule a member breaks (#1250). ([53f39c1](https://github.com/jscott3201/rusty-bacnet/commit/53f39c1cc1d4ac511cd8227cc80ddc7687d67c48))

- **Breaking (Rust API):** `BACnetLightingCommand` takes a `LightingOperation` and a
  `u8` priority, gains a codec in `bacnet_encoding::constructed`, and Lighting Output
  gains `set_lighting_command` and `lighting_command` (#1263). ([91ce62a](https://github.com/jscott3201/rusty-bacnet/commit/91ce62a13f533db07b8a6c5586c2facf75edeb03))

- **Rust API:** `TimeSyncSourceRestriction` refuses an entry longer than 18
  octets, which could never match a source (#1266). ([cf0d55a](https://github.com/jscott3201/rusty-bacnet/commit/cf0d55ae8c5788195aaee9fe3dac00566c6c2aaa))

- **Breaking (Rust API):** routed confirmed requests and the routed-path limit
  methods refuse a router MAC, local source MAC or DADR longer than 18 octets
  before the path is reserved, instead of failing later (#1267). ([cf0d55a](https://github.com/jscott3201/rusty-bacnet/commit/cf0d55ae8c5788195aaee9fe3dac00566c6c2aaa))

- Durable saves run on a writer thread of their own, so a slow disk no longer holds the object
  database lock; a list that can't be saved is still refused, an Audit notification is acknowledged
  only once durable, and `stop()` waits for queued saves (#1270, #1363). ([1d3eb21](https://github.com/jscott3201/rusty-bacnet/commit/1d3eb211c7700a20b59320ddf968c4fe8c269744))

- **Breaking (Rust API):** `EventLogDatum::Notification` holds a typed
  `EventNotificationRequest`, now in bacnet-types with its codec in
  bacnet-encoding. `decode_event_log_record` refuses a notification that isn't
  a valid request, but drops an unreadable message text (#1276). ([ea05d58](https://github.com/jscott3201/rusty-bacnet/commit/ea05d5890885085fd54f7e3e3f6a0d186434fda2))

- **Breaking (Rust API):** routed confirmed requests, `add_routed_device` and
  the endpoint requester refuse DNET 0, DNET 65535 and an empty DADR before any
  path or transaction state is taken, instead of sending a request no single
  device can answer (#1278). ([0618115](https://github.com/jscott3201/rusty-bacnet/commit/06181155fd7b7ca7992651dc2b1495692d8b034b))

- B/IP and B/IPv6 also take an Original-Unicast-NPDU's group-delivery flag from the address it was
  sent to (#1301). ([ccec56f](https://github.com/jscott3201/rusty-bacnet/commit/ccec56fc3d243a73b286c2333ae11179171300c2))

- **Rust API:** the ReadAccessSpecification, BACnetChannelValue, audit
  notification and formal Error body decoders report contents cut short as
  `Error::BufferTooShort` and a fixed-size field of the wrong length as
  `Error::Decoding`; Python error messages change, peer replies don't (#1303). ([c8830e3](https://github.com/jscott3201/rusty-bacnet/commit/c8830e320963a18028d798f8a26f896f01567ac9))

- **Rust API:** `bacnet_encoding::constructed::tagged` is public, and the
  service decoders read their parameters with it in place of their own
  helpers, so a member read through it that is cut short is
  `Error::BufferTooShort`; Python error messages change, peer replies don't
  (#1304). ([c5ab51e](https://github.com/jscott3201/rusty-bacnet/commit/c5ab51eb677d00887d549c27e8975e36b91829aa))

- **Breaking (Python API):** Recipient_List, a Group's members and
  Present_Value, a Command's Action and the other constructed lists the
  binding writes read as typed values. In 0.11.0 a local read gave the stored
  octets or flat list, and a client read only the first application-tagged
  value (#1310). ([e04ef28](https://github.com/jscott3201/rusty-bacnet/commit/e04ef2883cafe4f8b1a3958a3b5395928723a183))

- **Breaking (Rust API):** the Loop and Pulse Converter references read as
  `PropertyValue::ApplicationData`, and `decode_setpoint_reference` takes an empty value
  as no reference and refuses an empty frame (#1312). ([808e0c2](https://github.com/jscott3201/rusty-bacnet/commit/808e0c2903b79898c17009d9f583c1986c248fe0))

- **Breaking (wire):** device reference properties share one decode: anything after a single reference, a Trend Log's included, is INVALID_DATA_ENCODING, and a Staging target of another datatype INVALID_DATA_TYPE (#1313). ([7ade5e3](https://github.com/jscott3201/rusty-bacnet/commit/7ade5e36df847e9d7909ff6d4b9d7615824cd0f4))

- A Schedule's written reference list is decoded whole and held to its cap before any member's Device check, so a malformed member or the cap wins over an earlier member's refusal (#1313). ([7ade5e3](https://github.com/jscott3201/rusty-bacnet/commit/7ade5e36df847e9d7909ff6d4b9d7615824cd0f4))

- `NetworkLayer` sends that name a destination network refuse network 0 with an error saying so,
  before encoding or sending anything (#1314). ([ccec56f](https://github.com/jscott3201/rusty-bacnet/commit/ccec56fc3d243a73b286c2333ae11179171300c2))

- **Rust API:** The mutation authorizer decides each Channel write of an
  inbound WriteGroup; `DenyAll` denies them, and the decisions are counted
  (#1319). ([cbe62f3](https://github.com/jscott3201/rusty-bacnet/commit/cbe62f311b478671b7cafadb789affb2fbf238c9))

- **Breaking (Rust API):** `CovAckResult::Error` carries the refusing answer as a `Refusal`: the Error class and code, or the Reject or Abort reason (#1323). ([0863c0f](https://github.com/jscott3201/rusty-bacnet/commit/0863c0f590582684016b70b3ff1f89442509b2a5))

- **Rust API:** decoders report contents cut short as `Error::BufferTooShort`
  inside constructed frames, Error PDUs and timestamps too, and check a
  fixed-size application value's length before its contents. Python error
  messages change; peer replies don't (#1333). ([d54b143](https://github.com/jscott3201/rusty-bacnet/commit/d54b143114dbc71de28731df2362893a34824393))

- `NetworkLayer` routed and on-issuance sends refuse destination network 0xFFFF paired with a
  device address, naming the error, before encoding or sending anything (#1340). ([6d08557](https://github.com/jscott3201/rusty-bacnet/commit/6d08557f5bcffb5da3b43d5b96fca9ea8e58cc73))

- **Wire, Breaking (Rust API):** A Channel reads a remote member's datatype and
  coerces its value to it, so a remote Binary Output takes REAL 1.0 as ACTIVE;
  an unanswered read fails the member unsent, a refused one sends the value as
  written. `CovAckResult` gains `Data` (#1342). ([cbe62f3](https://github.com/jscott3201/rusty-bacnet/commit/cbe62f311b478671b7cafadb789affb2fbf238c9))

- **Breaking (Python API):** Access Zone Entry_Points and Exit_Points and
  Access User Credentials read as `device_object_reference` values, an
  `ObjectIdentifier` or a `(device, object)` pair, where a 0.11.0 local read
  gave plain object identifiers (#1344). ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Breaking (Python API):** Date_List, schedules, timestamps, Value_Source
  and the other constructed properties in
  [the Python API guide](docs/python-api.md#typed-constructed-values) read as
  typed values. In 0.11.0 a local read gave the stored octets or flat list,
  and a client read only the first application-tagged value (#1345). ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Breaking (wire, Rust API):** Trend Log refuses COV logging until the
  stack can do it (#1480), whether asked through Logging_Type or by writing a
  polled log's Log_Interval to zero; `TrendLogObject::set_logging_type`
  returns `Result` (#1354). ([1be8248](https://github.com/jscott3201/rusty-bacnet/commit/1be824832f0d675a17f3f3cf9846eb230287c57b))

- **Wire:** Once the client knows its network's number, `confirmed_request_routed` to that number
  ignores `router_mac` and sends the request straight to the DADR (#1358). ([f0c8d74](https://github.com/jscott3201/rusty-bacnet/commit/f0c8d74ce75c5cb897a613e53de97e7af83f544d))

- **Breaking (Python API):** an integer argument outside the type of the field
  it fills raises `OverflowError` everywhere, as a mapping value or tuple
  member as well as a parameter, instead of `ValueError` or
  `BacnetProtocolError` on some paths (#1360). ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Breaking (Rust API):** the bacnet-services decoders that still read tags
  inline use `bacnet_encoding::constructed::tagged`, so a member they read
  that is cut short is `Error::BufferTooShort`; `tags::decode_optional_context`
  is removed. Peer replies don't change (#1374). ([d682790](https://github.com/jscott3201/rusty-bacnet/commit/d68279070d0a21da717d84f10db7854b59a2f10b))

- `NetworkLayer` routed and on-issuance sends refuse destination network 0xFFFF
  with no device address too, pointing to `broadcast_global_apdu`, since a
  unicast global broadcast reaches only one router (#1380). ([520abe7](https://github.com/jscott3201/rusty-bacnet/commit/520abe781edc7613dfb2a38e0c8a20e2b31d6cdd))

- **Breaking (Rust API):** A value written directly to a Loop or Pulse
  Converter reference is decoded like a device reference, so a malformed list
  gets the same refusal code and an empty list clears Setpoint_Reference;
  WriteProperty answers are unchanged (#1395). ([8174d11](https://github.com/jscott3201/rusty-bacnet/commit/8174d1172eaf150a7d5a187578f1ce5703b1aa77))

- **Breaking (Rust API):** `BACnetServer::comm_state()` returns the new
  `DccState` (`Enable` or `DisableInitiation`) instead of a raw `u8`, since the
  server refuses DISABLE; the unreachable DISABLE request drops are gone
  (#1399). ([e9472a8](https://github.com/jscott3201/rusty-bacnet/commit/e9472a845f846dbb32285fdfbbc8e352d59dcac5))

- **Breaking (Rust API):** durable saves finish on a writer thread, so a `BACnetServer` dropped
  without `stop()` returns before storage settles, and in async code it hands its object database
  to the blocking pool rather than block a Tokio worker (#1270, #1409). ([9a24975](https://github.com/jscott3201/rusty-bacnet/commit/9a24975c693bb99f132fedcf73fe8474cbbb8263))

- **Wire:** an Accumulator without a configured Prescale no longer reads it as
  NULL; the property is absent until the application sets one (#1417). ([5555911](https://github.com/jscott3201/rusty-bacnet/commit/55559112ff4daadbb7570f8c29d3839ab53750a2))

- **Breaking (wire):** an unset Loop, Pulse Converter, Trend Log, Averaging or
  Event Enrollment reference reads as a reference to instance 4194303, which
  clears one when written, and a NULL written to it, or to Fault_Parameters,
  succeeds and changes nothing (#1417). ([5555911](https://github.com/jscott3201/rusty-bacnet/commit/55559112ff4daadbb7570f8c29d3839ab53750a2))

- **Python API:** reading an unset reference property returns
  `application_data` naming instance 4194303 instead of null, and
  `write_property_local` of null on one leaves it as it is (#1417). ([5555911](https://github.com/jscott3201/rusty-bacnet/commit/55559112ff4daadbb7570f8c29d3839ab53750a2))

- **Breaking (Rust API):** `BACnetServer::write_local` returns `Err` for an
  array index on a property that isn't an array or that the object doesn't
  have, where it used to write the property (#1426). ([be29d40](https://github.com/jscott3201/rusty-bacnet/commit/be29d40796389a10b85e418044307490bf0c2948))

- **Rust API:** `NotificationClass` and `AccessRightsObject` stay `UnwindSafe` and
  `RefUnwindSafe` when built with persistence (#1428). ([3bb57d6](https://github.com/jscott3201/rusty-bacnet/commit/3bb57d6f1eb518ed6c2b8010c33934d909a7133a))

- **Wire:** Multi-state Input and Value refuse an Alarm_Values entry past
  Number_Of_States with VALUE_OUT_OF_RANGE naming the element, over
  WriteProperty, the list services and CreateObject, instead of storing it
  (#1429). ([fe20bc5](https://github.com/jscott3201/rusty-bacnet/commit/fe20bc58092d5e07ad4d7e6b7796f60696472854))

- **Breaking (Python API):** `BACnetServer.comm_state()` returns
  `EnableDisable.ENABLE` or `EnableDisable.DISABLE_INITIATION` instead of 0 or 2
  (#1431). ([eeb9dd9](https://github.com/jscott3201/rusty-bacnet/commit/eeb9dd9c7fe2f666423d82a378a42592352367f1))

- **Rust API:** `ScheduleWrite` has a public `retry` field, set
  when a Schedule offers its value again only to the references that refused
  it (#1436). ([c223214](https://github.com/jscott3201/rusty-bacnet/commit/c2232141aa2e42d2ec0d641a7542fde6d443ad46))

- A Schedule whose reference was refused because the object it names didn't
  exist offers that object its value as soon as it is created, by CreateObject
  or a local `ObjectDatabase::add`, instead of at the next 60-second pass
  (#1440). ([5555911](https://github.com/jscott3201/rusty-bacnet/commit/55559112ff4daadbb7570f8c29d3839ab53750a2))

- **Breaking (wire, Rust API):** State_Text written whole on a multi-state
  object, by WriteProperty, WritePropertyMultiple or a CreateObject without
  Number_Of_States, or its size at index 0, sets Number_Of_States, refusing
  a shrink that would strand a state the object holds (#1443). ([d63feb9](https://github.com/jscott3201/rusty-bacnet/commit/d63feb908613f0550d858a19bef70a25ebc67796))

- **Breaking (Rust API):** `Error::Decoding` carries a `DecodingKind`,
  `Error::InvalidTag` is gone, and server handlers return a request's decode
  error as its `Error::Reject`. AtomicReadFile-ACK count, stream and trailing
  faults are decoding errors, not `Error::Reject` (#1446). ([d54b143](https://github.com/jscott3201/rusty-bacnet/commit/d54b143114dbc71de28731df2362893a34824393))

- **Python API:** an AtomicReadFile-ACK with more or fewer records than its
  count, or octets after its data, raises `BacnetError`, where it raised
  `BacnetRejectError` as if the device had rejected the request (#1446). ([d54b143](https://github.com/jscott3201/rusty-bacnet/commit/d54b143114dbc71de28731df2362893a34824393))

- The samples in `examples/rust/samples` are workspace members outside the
  default build. They share the workspace's `Cargo.lock` instead of keeping
  their own, which could go stale, and CI lints and tests them with the rest
  of the workspace (#1406, #1450). ([78fd518](https://github.com/jscott3201/rusty-bacnet/commit/78fd51855e00cf82c1b14154acfc6014a23c67ce))

- **Wire:** A DCC or time-sync allowlist entry routed through the server's known network number
  also admits that station's direct requests, and time sync's per-source budget counts a station's
  direct and relayed requests as one source (#1458). ([b07dc35](https://github.com/jscott3201/rusty-bacnet/commit/b07dc359cf5d2d0c43317b31462910b7d14e225d))

- **Python API:** `configure_audit_recipient` accepts an Address on network 0 or on one numbered
  1 to 65534, so a server can report to a logger named by its own network's number (#1460). ([b07dc35](https://github.com/jscott3201/rusty-bacnet/commit/b07dc359cf5d2d0c43317b31462910b7d14e225d))

- Issues, pull requests and CI moved from a private Forgejo to GitHub, keeping
  every issue number (#1472). Linux CI runs on GitHub-hosted runners, a PR
  merges only when its `CI OK` and `Native OK` checks pass, and runs on dev
  prune superseded Actions caches (#1471). ([06ff246](https://github.com/jscott3201/rusty-bacnet/commit/06ff2463aa83328f31afdc0004db4360540a4bf6))

- **Breaking (Rust API):** `NetworkLayer` broadcasts only an
  Unconfirmed-Request, naming any other PDU type it refuses, as does a routed
  send with no DADR; `send_apdu_routed_via_local_broadcast` refuses an empty
  DADR. A confirmed call to a broadcast or group address fails in Rust and
  Python (#1479). ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- **Breaking (Rust API):** `WhoIsRequest` and `WhoHasRequest` hold one
  `range: Option<DeviceInstanceRange>`, which the client's `who_is`,
  `who_is_directed`, `who_is_network` and `who_has` take as one argument, so
  a request can't carry one limit, or send one past instance 4194303 (#1483). ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- The server drops a Who-Is or Who-Has that doesn't decode before spawning a
  task for it, and counts it in the new `DiscoveryCounters::malformed_dropped`
  (#1483). ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- **Rust API:** `DiscoveryCounters` is `#[non_exhaustive]`, so
  counters can be added without a break (#1493). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Breaking (Rust API):** Building a `BACnetServer` fails when a
  `DeviceBinding`, as the device's own MAC or its router's, is any group
  address of the link, such as a multicast address or the broadcast IP at
  another port, not only its broadcast; the error names the device (#1493). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Python API:** `BACnetServer.start()` raises `BacnetError`, naming the
  device and the address, when `add_device_binding` gave a multicast address,
  255.255.255.255 or the broadcast IP at another port (#1493). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Breaking (Python API):** a `PropertyValue` date reads with the full year
  (2026, not 126) and an unspecified year as 255 (`UNSPECIFIED`); and
  `time_synchronization` and `utc_time_synchronization` take only a
  specific date and time, raising `ValueError` otherwise (#1501). ([17404bb](https://github.com/jscott3201/rusty-bacnet/commit/17404bb55178e00727f2431bc2ccbc44a87599ad))

- RPM, GetAlarmSummary, GetEnrollmentSummary, AtomicReadFile, ReadRange,
  GetEventInformation and AtomicWriteFile get local payload and response
  budgets; see the
  [service budget index](docs/request-admission.md#delivered-service-budgets).

- **Breaking (Rust and Python API):** a configured server's DCC authorization
  defaults to deny all, even with the right password, until a `DccPolicy` mode
  (Python: `dcc_policy`) is chosen.

- **Wire:** B/IPv6 with `::` or no interface picks one usable link and
  address, keeps its traffic on that link, and fails startup when the choice
  is ambiguous; it used to ask the routing table for an address and fall back
  to `::1`. ([3bdf951](https://github.com/jscott3201/rusty-bacnet/commit/3bdf9510caa0dcdca4df8d163cbf0693da196ad4))

- **Rust and Python API:** multi-device RP, RPM and WP batch limits take
  `Option<NonZeroUsize>` in Rust, and Python refuses zero with `ValueError`;
  `None` still means 32.

- The tracked repository-local `.codex/` configuration and agent profiles are
  removed.

- **Rust API:** `BACnetObject::configure_audit_reporter_internal` takes all
  five Reporter settings at once.

- **Rust and Python API:** WriteProperty request encoding returns `Result` and
  refuses priorities outside 1 to 16 before anything is sent.

### Removed

- **Breaking (Rust API):** `bacnet_server::handlers::handle_device_communication_control`
  is gone; no server called it, and it stored the DCC state as a raw integer under
  the permissive rules (#1430). ([eeb9dd9](https://github.com/jscott3201/rusty-bacnet/commit/eeb9dd9c7fe2f666423d82a378a42592352367f1))

- The conformance ledger, its generated pages (the support summary and the
  draft PICS and BIBBs) and their tooling are removed while conformance
  reporting is reworked for the docs website, whose
  [support page](https://jscott3201.github.io/rusty-bacnet/project/support/#whats-supported)
  summarizes what is supported. ([4b8a17a](https://github.com/jscott3201/rusty-bacnet/commit/4b8a17a99c11dd6704eac73f5b764d7d6fbc0c16))

### Fixed

- **Rust and Python API:** endpoint clients send ReadPropertyMultiple through
  the shared read path, with ordered ACK correlation and one source READ
  record per reference; RPM request encoding returns `Result` (#780).

- Target Audit Reporters can carry an optional Maximum_Send_Delay and Send_Now
  pair that batches ordinary records; see
  [delayed target Audit reporting](docs/delayed-target-audit.md) (#783).

- **Python API:** RP, RPM and WP batch results carry a zero-based
  `request_index`, and their item errors are typed `BacnetError` instances
  instead of strings (#788).

- **Breaking (Rust API):** single-property COV subscribe methods take a
  `NonZeroU32` lifetime, and the server refuses a zero lifetime with
  VALUE_OUT_OF_RANGE (#802).

- **Wire and Rust API:** SubscribeCOV request encoding returns `Result` and
  refuses a lifetime without a confirmed-notification mode, and the server
  refuses that shape too (#805).

- **Rust and Python API:** `SubscribeCOVPropertyMultipleRequest::encode`
  returns `Result` and validates the whole request first, and Python validates
  every entry before it sends anything (#808).

- **Wire:** an Analog or Binary Value Audit policy change reserves its
  notification before committing, and is refused with SERVICE_REQUEST_DENIED
  when it can't (#809).

- **Breaking (Rust API):** COV compares a typed sample with validated
  Status_Flags, so a status-only change passes the threshold and a late
  unconfirmed send can't replace a newer one; `last_notified_observation`
  replaces `last_notified_value` and its setter (#810, #817, #826, #833,
  #840).

- **Rust API:** COV subscription identity distinguishes exact endpoints,
  subscription families, array indexes and confirmed forms, and table lookup
  and cancellation take typed keys (#812).

- **Breaking (Rust API):** Event Enrollment evaluation reports through one
  `evaluate_event_enrollments_report`, which now includes reliability results;
  the duplicate detailed API is gone (#815).

- **Wire:** a finite COV notification no longer rounds a remaining lifetime
  under one second down to zero, which means indefinite (#819).

- **Wire:** specialized commandable Value_Source COV for AO, AV, BO, BV, MSO
  and MSV: reports carry Value_Source, Last_Command_Time and
  Current_Command_Priority with Present_Value and Status_Flags (#823).

- **Rust API:** the typed ValueSource codec prerequisite for #824:
  `BACnetValueSource::Object` carries a `BACnetDeviceObjectReference`, encoded
  by `encode_value_source` and `decode_value_source` (#824).

- **Breaking (Rust and Python API):** a six-family command-source producer
  tracks the source of each command on Analog, Binary and Multi-state Outputs
  and Values, and local writes name their source (#824).

- With several Device objects in the database, wildcard Device reads, COV
  lists, discovery and notifications consistently pick the lowest instance
  (#832).

- **Wire:** COV-multiple contexts match the original client whichever router
  it came through (#833).

- The served Device's service bits, COV lists, Property_List and RPM rows come
  from the server that runs them, and writes to these fields are refused
  (#834).

- **Wire:** a ReadPropertyMultiple response to a wildcard Device request names
  the concrete Device in each result (#835).

- PICS property rows combine every configured instance of an object type and
  sort by property ID (#838).

- **Wire:** ordinary COV subscriptions match the original recipient across
  routers (#840).

- **Breaking (wire):** Priority_Array is read-only on every commandable
  object; command or relinquish through Present_Value with a priority (#842).

- **Breaking (Rust and Python API):** `ObjectIdentifier` validates its object
  type and instance at construction, and `new_unchecked` is gone (#847).

- **Rust and Python API:** direct B/IP endpoints send WriteProperty through
  the shared requester with source Audit WRITE records, and callers state
  `Commandability` (Python: `commandability=`) (#852).

- Present but empty Audit Target_Value and Current_Value fields stay distinct
  from absent values and from NULL (#853).

- **Wire:** timestamped COV-multiple reports carry each change's commit time
  and keep it until delivered, honouring Max_Notification_Delay. An oversized
  report splits in capture order, value by value if need be; a value no
  notification can carry is dropped (#856, #986, #1008, #1090).

- **Python API:** the remaining 104 native methods that return futures are
  typed `def -> Awaitable[T]` instead of as coroutines (#858).

- Python B/IP, SC and MS/TP endpoint startup and close go through one owner,
  so close joins startup and a second start can't open a second transport
  (#861).

- **Rust API:** an explicitly registered NORMAL B/IP Network Port follows its
  actual bind and resolves wildcard reads (#863).

- NORMAL B/IP full servers and endpoints discover and learn their local
  Network Number, taking configured provenance only from explicit registration
  (#875, #863).

- **Python API:** the remaining 43 native futures that produce nothing now
  return `None` instead of an empty tuple (#865).

- **Breaking (Rust and Python API):** raw Network Port construction is
  replaced by a configured, unbound IPV4/NORMAL snapshot; Python uses
  `add_bip_network_port` (#867).

- **Wire:** a write of a property a built-in object doesn't have returns
  UNKNOWN_PROPERTY instead of a write-access error (#870).

- A full server's shutdown retires I-Am admission, joins admitted sends and
  stops its own transport, so a retained broadcaster handle no longer keeps
  the socket alive (#872).

- Full servers and shared endpoints on every other built-in link answer and
  learn local Network Number controls, each starting UNKNOWN (#879). ([a8194c1](https://github.com/jscott3201/rusty-bacnet/commit/a8194c1425cd192d59cee2ff010a296ff26ad6df))

- **Breaking (wire, Rust and Python API):** Default_Color, Default_Color_Temperature
  and Color_Command use their standard property identifiers 4194330, 4194331 and
  4194334 instead of 508 to 510, which name Network Port properties (#887). ([97baf49](https://github.com/jscott3201/rusty-bacnet/commit/97baf4921afafc2ae9018a0dd68706de4e879bcd))

- **Breaking (Rust API):** An Event Enrollment reference may name a property
  identifier above 4194303, where ASHRAE assigns some, such as Default_Color
  (#887). ([97baf49](https://github.com/jscott3201/rusty-bacnet/commit/97baf4921afafc2ae9018a0dd68706de4e879bcd))

- Changes committed by background tasks, such as alarm confirmations,
  reliability changes and schedule writes, reach COV subscribers at once
  (#889).

- **Wire:** COV criteria report only an actual change, so binary, multi-state
  and zero-increment subscribers no longer get repeats of the same value
  (#889).

- B/IP and B/IPv6 transports bound to port 0 no longer set `SO_REUSEADDR`,
  which on Linux could let two sockets share an ephemeral port and lose
  replies (#892).

- **Wire:** a confirmed COV notification advances the subscriber's baseline
  only once acknowledged, and a failed one is reported again after a hold-off
  (#896, #923). ([3598b86](https://github.com/jscott3201/rusty-bacnet/commit/3598b8644648ccbdbf6c97453594acb5e0a1a771))

- BACnet/SC connections disable Nagle's algorithm, so a small message no
  longer waits on the peer's delayed ACK; the transport tests run more than
  twice as fast on Linux CI (#900). ([1b99550](https://github.com/jscott3201/rusty-bacnet/commit/1b9955044bfb2876af3e6994283555169d43b6b8))

- **Breaking (wire, Rust and Python API):** the Who-Am-I, You-Are, VT and
  WriteGroup codecs encode as the Clause 21 grammar does, so conformant peers
  can decode them, and their request types change to match (#912). ([5ffc8a1](https://github.com/jscott3201/rusty-bacnet/commit/5ffc8a1a00c718762246839cba088b8c813d7f6e))

- **Breaking (Rust API):** the PICS generator's `CharacterSet` offers exactly
  Annex A's six character sets with their Annex A labels: `DbcsMs` and `Ansi`
  are gone, and `DbcsIbm` and `Jisx0208` become `IbmMicrosoftDbcs` and
  `JisX0208` (#913). ([83b3639](https://github.com/jscott3201/rusty-bacnet/commit/83b3639eeb2af753950a9913c5a38838865994d8))

- **Wire:** a B/IP BBMD forwards its own broadcasts to its BDT peers and
  foreign devices, takes its own address from its BDT when bound to `0.0.0.0`,
  and no longer rebroadcasts a broadcast Forwarded-NPDU locally (#937, #952). ([873fd0c](https://github.com/jscott3201/rusty-bacnet/commit/873fd0cc97b25f0d137ffa30fb27698e39f3be8a))

- The `bacnet` CLI no longer overflows the main thread's stack on Windows
  (#950). ([7abb5e4](https://github.com/jscott3201/rusty-bacnet/commit/7abb5e451793bca30c923e2244e6bba93efea336))

- A BACnet/SC dial to a host name with several addresses races them, Happy
  Eyeballs style, instead of trying each in turn (#950). ([7abb5e4](https://github.com/jscott3201/rusty-bacnet/commit/7abb5e451793bca30c923e2244e6bba93efea336))

- A peer that the SC hub or a direct-connection listener refuses during the
  TLS handshake can now read the alert that says why, instead of seeing a
  connection reset (#950). ([7abb5e4](https://github.com/jscott3201/rusty-bacnet/commit/7abb5e451793bca30c923e2244e6bba93efea336))

- On Windows, a B/IP or B/IPv6 transport on an ephemeral port sets
  SO_EXCLUSIVEADDRUSE, so another socket can't take its unicast (#950). ([7abb5e4](https://github.com/jscott3201/rusty-bacnet/commit/7abb5e451793bca30c923e2244e6bba93efea336))

- On Windows, a B/IP transport bound to `0.0.0.0` lists the host's IPv4
  addresses and accepts only unicast addressed to one of them, as on Linux and
  macOS (#952).

- Starting a server, client or SC connection, and running the CLI, take much
  less stack in a debug build, and the native jobs now test with 1 MiB thread
  stacks (#953). ([943cc20](https://github.com/jscott3201/rusty-bacnet/commit/943cc2071b05b7942c63d4cb9849db564bf3a353))

- **Wire:** Loop, Schedule and both Trend Log object types compute
  Status_Flags from their state instead of always reading all FALSE, and a
  Loop's flag changes reach COV subscribers (#978). ([d5f0be7](https://github.com/jscott3201/rusty-bacnet/commit/d5f0be714354749fd13483501e553bbdd8c2498e))

- **Breaking (wire):** the Access Credential no longer serves Present_Value,
  which its table doesn't define; read Credential_Status instead (#979). ([badb67c](https://github.com/jscott3201/rusty-bacnet/commit/badb67cce780470d1b952503642ac2f1561bd288))

- **Breaking (wire, Rust API):** the Elevator Group's Landing_Call_Control and
  Landing_Calls carry BACnetLandingCallStatus values, and the unused
  `BACnetAssignedLandingCalls` is removed (#980). ([c3bce1f](https://github.com/jscott3201/rusty-bacnet/commit/c3bce1f0bef2887d82760f2c6d48b89fbed83042))

- **Breaking (wire):** Calendar no longer serves Status_Flags, Event_State or
  Out_Of_Service, which its table doesn't define (#984). ([cc2fc21](https://github.com/jscott3201/rusty-bacnet/commit/cc2fc21bb61138b998cf5ccf507dedf899148970))

- **Wire:** a Loop's SubscribeCOV report carries Setpoint and
  Controlled_Variable_Value, the Loop gains Controlled_Variable_Value and
  COV_Increment, and its Present_Value is writable while out of service
  (#985). ([943b8fa](https://github.com/jscott3201/rusty-bacnet/commit/943b8fabc2cdc5d358a5ce4799cc797c5e214c5e))

- **Breaking (wire):** neither Trend Log object type serves Out_Of_Service any
  longer, as their tables don't define it (#985). ([943b8fa](https://github.com/jscott3201/rusty-bacnet/commit/943b8fabc2cdc5d358a5ce4799cc797c5e214c5e))

- **Wire:** a field subscribed with timestamps no longer goes out without a
  Time_Of_Change in a timestamped COV-multiple report (#987). ([e31f7c3](https://github.com/jscott3201/rusty-bacnet/commit/e31f7c34597704b402dffa4e5044900280df93bd))

- The Python B/IP endpoint tests bind port 0 and read the bound port back
  instead of probing for a free one (#993). ([52bfdeb](https://github.com/jscott3201/rusty-bacnet/commit/52bfdeb3b6a76c2b953ff8bbfe7a7155ceb76dad))

- **Breaking (wire, Rust API):** Calendar's Date_List and the Schedule's
  calendar entries, special events, daily schedules and Effective_Period use
  their Clause 21 encodings, and Date_List is network-writable (#996). ([107e9fa](https://github.com/jscott3201/rusty-bacnet/commit/107e9fa5fe54d0c990083ac264b833b06672833f))

- **Breaking (wire):** the Elevator Group drops Status_Flags, Out_Of_Service
  and Reliability, gains the required Machine_Room_ID, and refuses a Group_ID
  above 255 (#997). ([63682c3](https://github.com/jscott3201/rusty-bacnet/commit/63682c3cdfb0f8a61dcc3cc46dc77a6589844551))

- **Wire:** the Lift's Car_Moving_Direction accepts every
  BACnetLiftCarDirection value, and a new Lift reads STOPPED (#998). ([63682c3](https://github.com/jscott3201/rusty-bacnet/commit/63682c3cdfb0f8a61dcc3cc46dc77a6589844551))

- **Wire:** AddListElement and RemoveListElement answer PROPERTY_IS_NOT_A_LIST
  when the target isn't a BACnetLIST, decided by the new
  `BACnetObject::is_list_property` (#999). ([22c6df8](https://github.com/jscott3201/rusty-bacnet/commit/22c6df893438fb5455e6726c408a436d2e48730a))

- **Breaking (Python API):** a Python process no longer crashes at exit while
  a Tokio thread completes an awaited future. The bindings bridge Tokio to
  asyncio themselves instead of through `pyo3-async-runtimes` (#1002). ([52bfdeb](https://github.com/jscott3201/rusty-bacnet/commit/52bfdeb3b6a76c2b953ff8bbfe7a7155ceb76dad))

- **Breaking (wire, Rust API):** the Lift object serves its Table 12-77 rows
  in the table's datatypes, gains the required rows it lacked, and drops
  Tracking_Value and Floor_Number (#1021). ([8b92c95](https://github.com/jscott3201/rusty-bacnet/commit/8b92c95831394b7d8e19bb683967a724c289875c))

- **Breaking (wire):** the Escalator gains the required Elevator_Group,
  Group_ID and Installation_ID rows, and its Energy_Meter_Ref becomes a
  BACnetDeviceObjectReference (#1022). ([8b92c95](https://github.com/jscott3201/rusty-bacnet/commit/8b92c95831394b7d8e19bb683967a724c289875c))

- **Breaking (wire):** ReadRange reads only BACnetLIST properties and answers
  PROPERTY_IS_NOT_A_LIST for anything else; Recipient_List and
  List_Of_Object_Property_References now page by element (#1025). ([77a0a81](https://github.com/jscott3201/rusty-bacnet/commit/77a0a8179e490b3ba49d7140ed8040cb48e0f667))

- **Breaking (wire, Rust API):** AddListElement and RemoveListElement answer
  every error with a ChangeList-Error carrying the first failed element
  number, which the client returns as `Error::Structured` and Python as
  `first_failed_element_number` (#1026). ([d697b35](https://github.com/jscott3201/rusty-bacnet/commit/d697b35ad304bb2c5eb3c0455054932a4d3119a1))

- **Breaking (wire):** AddListElement leaves an element that is already
  present alone, and RemoveListElement refuses the whole request when an
  element is missing or of another datatype (#1027). ([d697b35](https://github.com/jscott3201/rusty-bacnet/commit/d697b35ad304bb2c5eb3c0455054932a4d3119a1))

- **Breaking (wire, Rust API):** Calendar's Present_Value follows the device's
  local date, and a Schedule evaluates in Clause 12.24.4 order within its
  Effective_Period, writing typed values at Priority_For_Writing to each
  target's array index (#1029, #1028, #845). ([5dc2537](https://github.com/jscott3201/rusty-bacnet/commit/5dc2537d6cd70588f76f74e85bfd459c94cf1f55))

- **Breaking (wire):** an array-index read of the Elevator Group's
  Group_Members answers as a BACnetARRAY: index 0 is the member count, and an
  index past the end fails with INVALID_ARRAY_INDEX (#1034). ([c88f61a](https://github.com/jscott3201/rusty-bacnet/commit/c88f61afece69424171fc35e970b7aefaf6703d8))

- The Lift's Car_Door_Status and Landing_Door_Status accept writes while
  Out_Of_Service is TRUE, so a test tool can simulate the car; the door count
  stays the application's (#1035). ([c88f61a](https://github.com/jscott3201/rusty-bacnet/commit/c88f61afece69424171fc35e970b7aefaf6703d8))

- **Wire:** untimestamped COV-multiple values too large for one notification,
  such as the initial report of a large SubscribeCOVPropertyMultiple, now go
  out in several notifications that each fit (#1038). ([ccb3bad](https://github.com/jscott3201/rusty-bacnet/commit/ccb3bad0f31b7c630e080525d83b6517e023de01))

- The SC hub handshake-deadline tests run on Tokio's paused clock, and the
  B/IP BBMD and B/IPv6 VMAC-collision tests retry with a fresh port when
  another socket takes theirs (#1042, #1032). ([9d4baf4](https://github.com/jscott3201/rusty-bacnet/commit/9d4baf4b1146ec70f5958285cf1d1b7ddc64abc4))

- ReadRange on the Device's Active_COV_Subscriptions and
  Active_COV_Multiple_Subscriptions pages the live subscriptions instead of
  answering OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED (#1046). ([ec9b5a3](https://github.com/jscott3201/rusty-bacnet/commit/ec9b5a304c97b11d43467976637c0a5138c8f4d2))

- **Breaking (Rust API):** the client decodes every Clause 21 structured error
  body, so a CreateObject, SubscribeCOVPropertyMultiple,
  ConfirmedPrivateTransfer or VTClose error returns its fields instead of
  timing out (#1047). ([0f43456](https://github.com/jscott3201/rusty-bacnet/commit/0f43456afa2ae49d066aa2875d2db1524e0e4966))

- **Python API:** `BacnetProtocolError` gains the structured error fields
  `first_failed_write_attempt`, `first_failed_subscription`, `vendor_id`,
  `service_number`, `error_parameters` and `vt_session_identifiers` (#1047). ([0f43456](https://github.com/jscott3201/rusty-bacnet/commit/0f43456afa2ae49d066aa2875d2db1524e0e4966))

- **Breaking (wire):** the server answers CreateObject and
  SubscribeCOVPropertyMultiple errors with their Clause 21 error bodies
  instead of a plain class and code (#1047). ([0f43456](https://github.com/jscott3201/rusty-bacnet/commit/0f43456afa2ae49d066aa2875d2db1524e0e4966))

- **Wire:** when an object refuses an AddListElement that adds several
  elements, the ChangeList-Error names the refused element (#1048). ([436dd01](https://github.com/jscott3201/rusty-bacnet/commit/436dd01dd5ff577d5cccf2a15e0ca91639969a94))

- **Breaking (wire, Rust API):** SubscribeCOVPropertyMultiple processes its
  references in order and stops at the first failure, keeping the ones before
  it; the subscription caps are checked per reference too (#1058, #1059). ([73a3b28](https://github.com/jscott3201/rusty-bacnet/commit/73a3b28ada3d2729431d0dcb7804a8ca3d417677))

- **Wire:** SubscribeCOV covers every Table 13-1 object type the stack builds,
  adding Access Point, Credential Data Input and Load Control, and each report
  carries the values its row names (#1061). ([9a2a7b7](https://github.com/jscott3201/rusty-bacnet/commit/9a2a7b72ef4945b3ed6593753f714585a0d75753))

- **Breaking (wire):** the Loop serves the required rows it left out:
  Controlled_Variable_Units, Action, Priority_For_Writing and the three
  gain-constant units. Python's `add_loop` takes them as keywords (#1062). ([f04e5e1](https://github.com/jscott3201/rusty-bacnet/commit/f04e5e1434bcf0f4400ba35cf5b939816d9d986b))

- **Breaking (wire):** fourteen object types drop properties their Clause 12
  tables don't define, such as Out_Of_Service on Command and Notification
  Class; reading one now fails with UNKNOWN_PROPERTY (#1064). ([8a748c2](https://github.com/jscott3201/rusty-bacnet/commit/8a748c258277400eff1029183fbffbff57cbd321))

- **Breaking (wire, Rust API):** a special event priority outside 1 to 16 now
  gets VALUE_OUT_OF_RANGE instead of INVALID_DATA_ENCODING, and
  `BACnetSpecialEvent::event_priority` is a `u64` (#1087). ([122b629](https://github.com/jscott3201/rusty-bacnet/commit/122b6295263ed98daa8f360d5a3c81a1a8b3bcc5))

- **Breaking (wire, Rust API):** a Notification Class Recipient_List holds at
  most 32 destinations, and `NotificationClass::add_destination` returns
  `Result` (#1098). ([2caee31](https://github.com/jscott3201/rusty-bacnet/commit/2caee311979e4311fd7f87d4e09bee815dee50ac))

- **Breaking (wire, Rust API):** a configured recipient's MAC is at most 18
  octets, routing holds every Notification Class to the 32-destination cap,
  and the flat Recipient_List form from before #152 is gone (#1098, #1124,
  #1125). ([2caee31](https://github.com/jscott3201/rusty-bacnet/commit/2caee311979e4311fd7f87d4e09bee815dee50ac))

- **Breaking (wire):** a SubscribeCOVPropertyMultiple reference that asks for
  timestamps while the Device has no valid clock is refused on its own, in
  request order, instead of refusing the whole request (#1102). ([6a8c79a](https://github.com/jscott3201/rusty-bacnet/commit/6a8c79a18934f40e828a40902e58eb3beaa1e810))

- **Breaking (Rust API):** every SC hub start method returns
  `Error::Transport` with the OS's `io::Error` when its bind fails, instead of
  `Error::Encoding` with the error's text (#1104). ([6a8c79a](https://github.com/jscott3201/rusty-bacnet/commit/6a8c79a18934f40e828a40902e58eb3beaa1e810))

- **Breaking (wire, Rust API):** the Global Group's Group_Members and
  Present_Value go out in their Clause 21 forms, and an indexed read of its
  arrays returns one element (#1107). ([0980c10](https://github.com/jscott3201/rusty-bacnet/commit/0980c10774260915fc65845d99e8fa05b07fee5f))

- **Breaking (wire):** an Access Door accepts Door_Status, Lock_Status and
  Door_Alarm_State writes while Out_Of_Service is TRUE, so a client can
  simulate the door (#1131). ([533aad0](https://github.com/jscott3201/rusty-bacnet/commit/533aad09c2831da43a0db8274cb43d3087989d15))

- **Breaking (wire, Rust API):** Load Control shed levels, Access Point
  Access_Event_Time and Credential Data Input Update_Time and Present_Value use
  their standard datatypes, and Requested_Shed_Level accepts the standard
  write form (#1133). ([0debbca](https://github.com/jscott3201/rusty-bacnet/commit/0debbcadb03353f5b065c76b9207f97219248d33))

- **Breaking (wire, Rust API):** the Group object serves List_Of_Group_Members
  and Present_Value in their Table 12-17 datatypes, and rebuilds Present_Value
  from the members on every read (#1134). ([9217089](https://github.com/jscott3201/rusty-bacnet/commit/9217089a8c6dd561c5dcb096738f3d58a8fb42c1))

- **Breaking (wire, Rust API):** an indexed read of Subordinate_List,
  Subordinate_Annotations or Action returns one element, and Subordinate_List
  and Action elements go out in their Clause 21 forms (#1135). ([b7f1209](https://github.com/jscott3201/rusty-bacnet/commit/b7f12093227a886113ca8d63eb6f488a65e185cb))

- **Breaking (wire, Rust API):** the network layer drops and counts an NPDU
  whose DLEN or SLEN exceeds 18 octets, a router rejects one naming a DNET
  with reason 6, and `decode_npdu` returns `NpduDecodeError` (#1141). ([fe9175b](https://github.com/jscott3201/rusty-bacnet/commit/fe9175b409b011af1c95e9b02f58d3e0f001b824))

- **Wire:** an Access Door works out Secured_Status from its command, alarm,
  door and lock state on every read instead of always reading SECURED (#1148). ([03161a6](https://github.com/jscott3201/rusty-bacnet/commit/03161a636b181815c61996ab717a176855bb1875))

- **Wire:** AddListElement and RemoveListElement report a COV change the edit makes,
  as WriteProperty does, even when no event transition follows (#1149). ([a81304f](https://github.com/jscott3201/rusty-bacnet/commit/a81304f82c9a7d51a0d8b8f5d325ba698d6f5e33))

- Command and Channel runs that write back into their own object, directly or
  through others, stop after one round (#1151). ([36d8b72](https://github.com/jscott3201/rusty-bacnet/commit/36d8b7227baafbc1629420e642d16c248aeefe8c))

- **Wire:** an Averaging Object_Property_Reference naming this device is
  accepted and stored as a local reference; one naming another device is
  refused with OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED (#1153). ([db640e5](https://github.com/jscott3201/rusty-bacnet/commit/db640e5887b2f89cf381af9522de5ffef8379473))

- **Wire:** a recipient's Abort, which carries the server flag, now ends a
  confirmed notification this device sent, and an Abort with the flag clear no
  longer does (#1155). ([b8309cb](https://github.com/jscott3201/rusty-bacnet/commit/b8309cb9216be951f8e5cadb6b7a7eec0deffd2c))

- **Breaking `BACnetAddress` MAC bound (wire, Rust API):** every recipient,
  ValueSource and AuditLogQuery address codec now refuses a MAC longer than
  `BACnetAddress::MAX_MAC_LEN` (18 octets) in both directions, and the
  recipient encoders return `Result` (#1156). ([0696eb8](https://github.com/jscott3201/rusty-bacnet/commit/0696eb861cae65a1c4a855bdb0ddbcc4c48aa3fb))

- **Breaking (wire):** router rejects go back to whoever first sent
  the refused NPDU, using its SNET/SADR, and a received reject is relayed by
  its DNET/DADR (#1158). ([83cb97e](https://github.com/jscott3201/rusty-bacnet/commit/83cb97e51059fa6961561e7cbd5832d0a8d4428d))

- **Breaking (wire):** Credential Data Input takes Present_Value and Reliability
  writes while out of service, checked against its declared formats, and still
  refuses them in service (#1168). ([3498938](https://github.com/jscott3201/rusty-bacnet/commit/349893897dee41017d160c9683e7593828754c1e))

- **Breaking (wire):** Credential Data Input Supported_Formats and
  Supported_Format_Classes, Access Door Door_Members and Access Point
  Access_Doors are served as arrays in their Clause 21 element forms, with new
  setters (#1169). ([3498938](https://github.com/jscott3201/rusty-bacnet/commit/349893897dee41017d160c9683e7593828754c1e))

- A Group member that names the Device's Active_COV_Subscriptions or
  Active_COV_Multiple_Subscriptions now reads the live subscription list
  instead of an empty one (#1171). ([15a787f](https://github.com/jscott3201/rusty-bacnet/commit/15a787fb2dc82d3811ce3d6a8070304a7f444d36))

- **Router rejects for a node on the arrival link (wire):** when a refused
  NPDU's SNET is the arrival port's own network, `BACnetRouter` now sends the
  reject as a local unicast to its SADR instead of addressing it with a DNET
  that a non-router discards (#1174). ([5c1afb3](https://github.com/jscott3201/rusty-bacnet/commit/5c1afb3f1dc2e9a65b25866709c67799f0f34046))

- Away from the bundled server, `tick_schedules` runs the Command lists it starts, and the bare write handlers end the runs they can't make as unsuccessful, so In_Process doesn't stay TRUE (#1178). ([4c20f13](https://github.com/jscott3201/rusty-bacnet/commit/4c20f135e523b39e53e1dba60f6181545998a259))

- **Breaking (wire):** Averaging and Event Enrollment Object_Property_Reference
  and Life Safety Member_Of and Zone_Members are served as context-tagged
  device references, Life Safety Zone gains Member_Of, and Averaging refuses
  the old flat form (#1182). ([11c55eb](https://github.com/jscott3201/rusty-bacnet/commit/11c55eb65924f8de11ace8c20cf57f330dfbb451))

- **Trend Log polling (wire):** a Log_DeviceObjectProperty naming another
  device logs a failure record instead of a same-numbered local object's
  value, and a failed local read logs its error instead of a null value
  (#1183). ([4cbc93b](https://github.com/jscott3201/rusty-bacnet/commit/4cbc93b72a153302b35407a7aea5a9e3d7af4a05))

- **Event Enrollment references:** a FLOATING_LIMIT setpoint reference naming
  this device is read and reported, and with several Devices every enrollment
  reference treats the lowest one as this device (#1184). ([4cbc93b](https://github.com/jscott3201/rusty-bacnet/commit/4cbc93b72a153302b35407a7aea5a9e3d7af4a05))

- **Breaking (custom transports):** `NetworkLayer` and `BACnetRouter` drop a
  frame whose link-layer source MAC is longer than 18 octets and count it in
  `address_length_drops()`; no built-in transport reports one (#1198). ([981024a](https://github.com/jscott3201/rusty-bacnet/commit/981024a31d3bcb15fcb5d84136a4fb4c2d16e546))

- **Breaking (wire, Rust API):** `YouAreRequest` refuses a device MAC address
  longer than 18 octets on decode and encode (#1200). ([981024a](https://github.com/jscott3201/rusty-bacnet/commit/981024a31d3bcb15fcb5d84136a4fb4c2d16e546))

- **Trend Log indexed references (wire):** the poller logs the array element a
  Log_DeviceObjectProperty index names, and a failure for an index past the end
  or on a property that is not an array (#1205). ([eb86197](https://github.com/jscott3201/rusty-bacnet/commit/eb8619781f2917baa381a61d65fd671dc76bf987))

- **Router rejects for a looped NPDU (wire):** when a refused NPDU's SNET is
  another of the router's networks, the reject goes out that port as a local
  unicast to the SADR; when its SNET/SADR is the router itself, none is sent
  (#1219). ([ff7ba6b](https://github.com/jscott3201/rusty-bacnet/commit/ff7ba6b9ad49359a00b46453334c83a8fd7dafb0))

- **Breaking (wire):** ReadRange serves Trend Log and Event Log records framed as BACnetLogRecord and
  BACnetEventLogRecord, with encoders and decoders in `bacnet_encoding::constructed` (#1233). ([e1d1d0d](https://github.com/jscott3201/rusty-bacnet/commit/e1d1d0d35367438d4da43b1e6bf76e0240cf95af))

- **Breaking:** Log objects refuse a record that would not encode when it is added, and the
  pollers log an any-value over 256 octets as PROPERTY / VALUE_TOO_LONG, so every stored record
  can be served (#1233, #1236). ([e1d1d0d](https://github.com/jscott3201/rusty-bacnet/commit/e1d1d0d35367438d4da43b1e6bf76e0240cf95af))

- **Breaking (wire):** Log records (Trend, Event, Trend Log Multiple and Audit Log) send and read
  BACnetLogStatus bit 0 first, so log-disabled goes out as `05 80`, not as log-interrupted (#1233). ([e1d1d0d](https://github.com/jscott3201/rusty-bacnet/commit/e1d1d0d35367438d4da43b1e6bf76e0240cf95af))

- **Breaking (wire):** Trend Log and Trend Log Multiple serve and accept
  Log_DeviceObjectProperty as a context-tagged reference, Trend Log Multiple's
  as an indexable array, and a written change purges the log (#1234). ([11c55eb](https://github.com/jscott3201/rusty-bacnet/commit/11c55eb65924f8de11ace8c20cf57f330dfbb451))

- **Breaking (wire):** The trend pollers (Trend Log Multiple too) log a CharacterString, Double,
  array or other unlisted datatype as an any-value carrying its encoding instead of NULL (#1236). ([e1d1d0d](https://github.com/jscott3201/rusty-bacnet/commit/e1d1d0d35367438d4da43b1e6bf76e0240cf95af))

- **Breaking (wire):** Trend Log, Trend Log Multiple and Event Log answer ReadProperty and RPM of
  Log_Buffer with READ_ACCESS_DENIED; ReadRange still reads it (#1237). ([e1d1d0d](https://github.com/jscott3201/rusty-bacnet/commit/e1d1d0d35367438d4da43b1e6bf76e0240cf95af))

- **Breaking (wire):** Access Zone takes Occupancy_Count and Reliability writes
  while out of service and serves its own values again on the return to service
  (#1247). ([af88659](https://github.com/jscott3201/rusty-bacnet/commit/af88659febed76ebbf8cd63ece71bf0d68e760c4))

- **Breaking (wire):** Access Point records an OUT_OF_SERVICE or
  OUT_OF_SERVICE_RELINQUISHED access event, with a new tag and time, each time
  Out_Of_Service changes (#1248). ([af88659](https://github.com/jscott3201/rusty-bacnet/commit/af88659febed76ebbf8cd63ece71bf0d68e760c4))

- **Rust API:** Credential Data Input keeps Present_Value to a
  declared format, and Python can now declare formats and set Door_Members and
  Access_Doors (#1249). ([af88659](https://github.com/jscott3201/rusty-bacnet/commit/af88659febed76ebbf8cd63ece71bf0d68e760c4))

- `BACnetServer::stop()` ends each Command or Channel run it cancels, or that never started, where it stood, with its unmade writes unsuccessful, so none stays In_Process or IN_PROGRESS (#1252). ([2a8495a](https://github.com/jscott3201/rusty-bacnet/commit/2a8495a32cb03363e7f8712697e215ee526d2f7e))

- **Breaking (wire):** The server ignores a confirmed request sent by broadcast or multicast,
  whatever the service, instead of executing and answering it, so the Notification Forwarder never
  forwards one (#1257). ([76b2b84](https://github.com/jscott3201/rusty-bacnet/commit/76b2b84f0d75ce1d0d2b7a17713c10dbfaf5a945))

- **Breaking (wire):** Lighting Output serves and takes Lighting_Command as a
  BACnetLightingCommand checked against its operation, refusing the old octet string,
  and takes the lighting commands a Channel or WriteGroup passes to it (#1263). ([91ce62a](https://github.com/jscott3201/rusty-bacnet/commit/91ce62a13f533db07b8a6c5586c2facf75edeb03))

- The Notification Forwarder's file backend synchronizes its directory after each rename, and the
  Audit Log's when it creates a slot, so a completed save survives a power loss (not on Windows)
  (#1270). ([1d3eb21](https://github.com/jscott3201/rusty-bacnet/commit/1d3eb211c7700a20b59320ddf968c4fe8c269744))

- **Breaking (Rust API):** Setters and write paths that store device object
  references, Channel members included, refuse a device identifier that isn't
  a Device object; Python raises `ValueError` (#1285). ([9cd82bc](https://github.com/jscott3201/rusty-bacnet/commit/9cd82bc9c4126d5fa0953099a9fa5fdd898e52c2))

- **Breaking (wire):** the array and list classification covers every array of
  the 2020 object tables, Lift and Network Port included. An indexed read of an
  array an object lacks answers UNKNOWN_PROPERTY, and Access Rights serves its
  rule arrays as empty arrays (#1296). ([ce572cf](https://github.com/jscott3201/rusty-bacnet/commit/ce572cf812e35750d255bfc885eb5ebdfe364548))

- **Breaking (Python API):** read results keep every element of a value. A whole
  array or list reads as a `list` at any length, several values as a `list`, and
  context-tagged or otherwise unrepresentable content as `application_data`
  octets; only broken framing raises (#1296). ([ce572cf](https://github.com/jscott3201/rusty-bacnet/commit/ce572cf812e35750d255bfc885eb5ebdfe364548))

- **Breaking (Python API):** `BACnetServer.read_property` reads through the
  server's ReadProperty evaluator and `write_property_local` decodes its value
  as a network WriteProperty does, so local reads and writes match network ones
  and what one reads writes back (#1297). ([ce572cf](https://github.com/jscott3201/rusty-bacnet/commit/ce572cf812e35750d255bfc885eb5ebdfe364548))

- **Breaking (wire):** Notification Class notifications and forwarded copies to a recipient
  naming the local network's number go as local traffic with no DNET, so non-routing nodes
  there receive them (#1299). ([5e66d84](https://github.com/jscott3201/rusty-bacnet/commit/5e66d84a1278aa6fd8795cc2487653d77334fad7))

- An AddListElement or RemoveListElement that moves an object into or out of
  alarm, such as an Alarm_Values edit, starts the transition at once, as
  WriteProperty does, instead of at the next periodic tick (#1305). ([bbf4acb](https://github.com/jscott3201/rusty-bacnet/commit/bbf4acb25aa4100df6fd1c289ff56cc71473376a))

- **Wire:** Access Zone serves Entry_Points and Exit_Points as lists of
  device object references to Access Points, set through new setters and
  Python keyword arguments (#1306). ([bbf4acb](https://github.com/jscott3201/rusty-bacnet/commit/bbf4acb25aa4100df6fd1c289ff56cc71473376a))

- **Breaking (wire, Rust API):** Schedule references, Global Group members, Command actions and the Event Enrollment reference refuse a non-Device device identifier with VALUE_OUT_OF_RANGE, and Python `add_command` raises ValueError (#1308). ([7ade5e3](https://github.com/jscott3201/rusty-bacnet/commit/7ade5e36df847e9d7909ff6d4b9d7615824cd0f4))

- **Breaking (wire):** the Loop's three references and Pulse Converter Input_Reference
  are served and written in their context-tagged forms, refusing the old flat list, and
  Averaging treats a reference that doesn't open with tag [0] as the wrong datatype (#1312). ([808e0c2](https://github.com/jscott3201/rusty-bacnet/commit/808e0c2903b79898c17009d9f583c1986c248fe0))

- A `write_local` dropped after its write committed, by a timeout or a
  `select!`, ends the Command or Channel run it started as if none of its
  writes were made (#1324). ([b7c351b](https://github.com/jscott3201/rusty-bacnet/commit/b7c351b2ec8fa5ddbb8fbb4d9d57a3f911b6714b))

- **Wire:** a confirmed COV or event notification outstanding when DeviceCommunicationControl
  disables initiation is no longer retried; it ends at its next retry and frees its invoke ID (#1327). ([74849ac](https://github.com/jscott3201/rusty-bacnet/commit/74849ac85e43e2ad193fd950f670f3858de135f5))

- **Wire:** WriteProperty and WritePropertyMultiple hand a list property to the
  object as a list at every length, so an empty value clears Alarm_Values; an
  empty write to a read-only or unserved list is now WRITE_ACCESS_DENIED or
  UNKNOWN_PROPERTY, not INVALID_DATA_ENCODING (#1328). ([cc8e7c0](https://github.com/jscott3201/rusty-bacnet/commit/cc8e7c01f528f3a8de45cbf205f8d4a8bea119d0))

- **Wire:** a Pulse Converter reports a configuration fault while its
  Input_Reference names a property it can't count from, re-checked as objects
  come and go, takes a simulated Reliability out of service, and a running
  server counts that property's increases into Count (#1341). ([5555911](https://github.com/jscott3201/rusty-bacnet/commit/55559112ff4daadbb7570f8c29d3839ab53750a2))

- A Channel writes each member when its own Execution_Delay is up, so a member
  in another device that waits for its answer doesn't delay the others; runs
  send each device one request at a time and at most 32 in all, and Reliability
  names the first failure to finish (#1343). ([cbe62f3](https://github.com/jscott3201/rusty-bacnet/commit/cbe62f311b478671b7cafadb789affb2fbf238c9))

- **Wire:** Command and Channel writes in another device, Audit notifications and forwarded
  Audit copies, and client requests and network broadcasts that name the local network's
  number go as local traffic with no DNET, so non-routing nodes there receive them (#1358). ([f0c8d74](https://github.com/jscott3201/rusty-bacnet/commit/f0c8d74ce75c5cb897a613e53de97e7af83f544d))

- **Wire:** A confirmed Audit notification whose Audit Log commit fails is refused with DEVICE /
  OPERATIONAL_PROBLEM instead of SERVICES / OTHER (#1366). ([b07dc35](https://github.com/jscott3201/rusty-bacnet/commit/b07dc359cf5d2d0c43317b31462910b7d14e225d))

- **Breaking (Rust API):** local writes (`write_local`, `set_present_value_local` and the like) must
  run inside a Tokio runtime, failing and writing nothing outside one; once committed, their COV, event,
  Schedule and Staging work finishes even if the caller is dropped (#1367). ([aef70c4](https://github.com/jscott3201/rusty-bacnet/commit/aef70c43149af99d5c3dcc3d36d5ccc3313f7eb1))

- **Python API:** a local write such as `write_property_local` or `set_present_value_local` whose
  asyncio task is cancelled after the write committed still sends its COV and event notifications
  and runs the Command or Channel it started (#1367). ([aef70c4](https://github.com/jscott3201/rusty-bacnet/commit/aef70c43149af99d5c3dcc3d36d5ccc3313f7eb1))

- **Wire:** audit notifications and Audit Log forwards keep going out while DCC disables initiation,
  as Clause 16.1 allows, and writes that owe an audit record get a SimpleACK there instead of
  SERVICE_REQUEST_DENIED (#1370). ([34165da](https://github.com/jscott3201/rusty-bacnet/commit/34165da9eeaa9dfa0d0d440122ef2f489e3904c2))

- **Wire:** a confirmed event notification whose Device recipient's observed binding expires before a
  retry now ends at that retry and frees its invoke ID, counted in `device_recipient_unbound` (#1371). ([aef70c4](https://github.com/jscott3201/rusty-bacnet/commit/aef70c43149af99d5c3dcc3d36d5ccc3313f7eb1))

- **Breaking (wire, Rust API):** a DeleteObject request whose object
  identifier is under any tag but its application tag is refused with
  SERVICES / OTHER instead of deleting the object; I-Have decoding refuses
  such members too (#1374). ([d682790](https://github.com/jscott3201/rusty-bacnet/commit/d68279070d0a21da717d84f10db7854b59a2f10b))

- **Breaking (wire, Rust API):** AtomicReadFile and AtomicWriteFile requests
  with a member under any tag but its application tag are refused with
  SERVICES / OTHER instead of being served (#1375). ([d682790](https://github.com/jscott3201/rusty-bacnet/commit/d68279070d0a21da717d84f10db7854b59a2f10b))

- **Wire:** `NetworkLayer` and `BACnetRouter` drop an inbound NPDU whose DNET
  0xFFFF also carries a DADR and count it in `global_broadcast_dadr_drops()`;
  the router no longer passes such an NPDU on to its other networks (#1379). ([520abe7](https://github.com/jscott3201/rusty-bacnet/commit/520abe781edc7613dfb2a38e0c8a20e2b31d6cdd))

- **Wire:** Lighting Output refuses a Lighting_Command_Default_Priority of 6,
  the priority kept for Minimum On/Off (#1384). ([b9ad662](https://github.com/jscott3201/rusty-bacnet/commit/b9ad6626f88014b09126ec57860110a6667fbbc9))

- **Wire:** Lighting Output stores a Present_Value or Relinquish_Default level
  above 0.0 and below 1.0 as 1.0, and -0.0 as 0.0. Tracking_Value, which
  always read 0.0, now follows Present_Value on every write (#1385). ([432a832](https://github.com/jscott3201/rusty-bacnet/commit/432a832dc68e81f6cb3f6395a0d1c7140fdd633b))

- **Breaking (wire):** Color and Color Temperature serve and take Color_Command as
  a BACnetColorCommand checked against the operations each object allows, refusing
  the old octet string (#1386). ([97baf49](https://github.com/jscott3201/rusty-bacnet/commit/97baf4921afafc2ae9018a0dd68706de4e879bcd))

- **Breaking (wire, Rust API):** While DeviceCommunicationControl's
  DISABLE_INITIATION is in force, the server no longer answers Who-Has with
  I-Have, and `broadcast_i_am()` sends nothing and returns an error; Who-Is
  still gets its I-Am (#1388). ([cd9c650](https://github.com/jscott3201/rusty-bacnet/commit/cd9c650d1042f0aeb9501c94785e821a545a1dc3))

- **Wire:** CreateObject decodes each initial value as WriteProperty does: a
  list such as Alarm_Values arrives as a list at any length, a scalar with a
  trailing element is INVALID_DATA_TYPE instead of keeping the first, and an
  index on a non-array is PROPERTY_IS_NOT_AN_ARRAY (#1389). ([a00da01](https://github.com/jscott3201/rusty-bacnet/commit/a00da01e6b4481e11f8b7b82b67822c5dda2bf05))

- **Wire:** Access User Credentials reads as a list of device
  object references instead of bare object identifiers, so it can name a
  credential held by another device (#1394). ([7cd802c](https://github.com/jscott3201/rusty-bacnet/commit/7cd802cb427216243a764e67f1b136e533a931ac))

- **Wire:** a NULL to a non-commandable property with no NULL in its datatype
  now succeeds unchanged over WP, WPM and local writes, not INVALID_DATA_TYPE.
  A Value_Source correction by a non-owner is WRITE_ACCESS_DENIED even when
  its value is malformed (#1396). ([32bc642](https://github.com/jscott3201/rusty-bacnet/commit/32bc64274fa26b0da548472b72694b4094e5db62))

- **Wire and Rust API:** Access Zone refuses NORMAL in Alarm_Values, as
  the Access Door does in its alarm lists, since alarming on NORMAL would put a
  zone in alarm while its count sits inside its limits (#1401). ([5b86027](https://github.com/jscott3201/rusty-bacnet/commit/5b86027bd48101bfac12038bf32dce517e6e8801))

- **Wire:** The shared endpoint publishes its network's number, so its routed reads naming that
  number, and source Audit records to an address on that network, go as local traffic with no DNET,
  which non-routing peers receive (#1403). ([8534bb1](https://github.com/jscott3201/rusty-bacnet/commit/8534bb121b08a748d140347cb0d02efa37db3e88))

- **Wire:** A request from a Device bound through the server's own network number, direct or
  relayed with that number as its SNET, is tied to that Device, so its Audit records and
  Value_Source name the Device instead of its address (#1404). ([8c06f00](https://github.com/jscott3201/rusty-bacnet/commit/8c06f00daab5ac67a34f8b11addf1bec71f7e37c))

- **Breaking (wire, Rust and Python API):** service decoders, `IHaveRequest`,
  `AtomicWriteFileAck` and `PrivateTransferAck` included, refuse trailing
  octets: the server refuses or drops such requests, the client ignores such an
  I-Am, and `confirmed_private_transfer` raises `BacnetError` (#1411). ([4ec1404](https://github.com/jscott3201/rusty-bacnet/commit/4ec14048e8ef00eed8506f3c9e745c1be46e776e))

- **Wire:** a NULL to a non-commandable property with no NULL in its datatype
  now succeeds unchanged as a CreateObject initial value and as a Schedule's
  target write, not INVALID_DATA_TYPE (#1416). ([a00da01](https://github.com/jscott3201/rusty-bacnet/commit/a00da01e6b4481e11f8b7b82b67822c5dda2bf05))

- **Wire:** `write_local`, Command and Channel local writes and Schedule
  target writes refuse an array index as WriteProperty does
  (PROPERTY_IS_NOT_AN_ARRAY, or UNKNOWN_PROPERTY) instead of writing the
  whole property; a Schedule's NULL to such a reference now fails (#1426). ([be29d40](https://github.com/jscott3201/rusty-bacnet/commit/be29d40796389a10b85e418044307490bf0c2948))

- **Breaking (wire):** a Schedule reference naming a missing object or property, or an
  array index the property can't take, sets the Schedule's Reliability to
  CONFIGURATION_ERROR until a write to it succeeds or it leaves the list
  (#1433). ([be29d40](https://github.com/jscott3201/rusty-bacnet/commit/be29d40796389a10b85e418044307490bf0c2948))

- **Wire:** an Object_Name already in use is refused with the PROPERTY error
  class instead of OBJECT, over WriteProperty, WritePropertyMultiple,
  CreateObject, local writes and `ObjectDatabase::add` (#1434). ([b687282](https://github.com/jscott3201/rusty-bacnet/commit/b687282bf2972e8ee875f54582cdd61f8b5259c1))

- **Wire:** a Schedule offers its value again, each pass, to the references that
  refused it, so CONFIGURATION_ERROR clears and the target gets the value once
  the cause is gone, such as a missing object being created (#1436). ([c223214](https://github.com/jscott3201/rusty-bacnet/commit/c2232141aa2e42d2ec0d641a7542fde6d443ad46))

- **Wire:** CreateObject no longer fails when another object holds the default
  name of the new one. That name is now the type and instance (`BINARY_VALUE-2`,
  not `ObjectType::BINARY_VALUE-2`), with the first free ` (n)` added when it
  is taken (#1437). ([fe20bc5](https://github.com/jscott3201/rusty-bacnet/commit/fe20bc58092d5e07ad4d7e6b7796f60696472854))

- **Breaking (wire):** a confirmed request the server can't decode now draws
  a Reject naming the fault, for every service, where some drew an Error, and
  some it already rejected get a different reason. The client rejects
  malformed notifications the same way (#1446). ([d54b143](https://github.com/jscott3201/rusty-bacnet/commit/d54b143114dbc71de28731df2362893a34824393))

- **Breaking (wire):** a Who-Is carrying only one of its two limits is
  malformed: `WhoIsRequest::decode` refuses it and the server drops it, where
  it used to answer as if the request named every device (#1447). ([d54b143](https://github.com/jscott3201/rusty-bacnet/commit/d54b143114dbc71de28731df2362893a34824393))

- **Wire:** The server's target Audit takes an Address recipient naming its own network number as
  local, sending to its MAC with no DNET; one whose network the number does not name, unknown or
  different, starts unresolved and resolves once it does (#1460). ([b07dc35](https://github.com/jscott3201/rusty-bacnet/commit/b07dc359cf5d2d0c43317b31462910b7d14e225d))

- **Wire:** A target Audit recipient change away from an Address the network number does not name
  goes ahead: the new recipient gets the record and an unconfirmed global broadcast replaces the old
  one's copy, and Reporter health follows each change of number (#1460). ([b07dc35](https://github.com/jscott3201/rusty-bacnet/commit/b07dc359cf5d2d0c43317b31462910b7d14e225d))

- **Wire:** An endpoint source Audit recipient Address whose network the session's number does not
  name, unknown or different, starts unresolved; a change away from it goes to the new recipient
  and by unconfirmed global broadcast (#1461). ([b07dc35](https://github.com/jscott3201/rusty-bacnet/commit/b07dc359cf5d2d0c43317b31462910b7d14e225d))

- **Wire:** Once the local network number is known, the client, the shared
  endpoint and the server complete a request whose answer a router relays back
  with that number as its SNET and the station as its SADR, instead of timing
  out (#1465). ([520abe7](https://github.com/jscott3201/rusty-bacnet/commit/520abe781edc7613dfb2a38e0c8a20e2b31d6cdd))

- **Wire:** a Trend Log classes Start_Time, Stop_Time, Log_Interval and
  Log_DeviceObjectProperty as required, so ReadPropertyMultiple with
  REQUIRED returns them and the PICS lists them as required (#1481). ([d3529d5](https://github.com/jscott3201/rusty-bacnet/commit/d3529d5154f715f4d99a641555949bd17a0b6b58))

- **Python API:** `who_is`, `discover`, `who_is_directed`, `who_has_by_id`
  and `who_has_by_name` raise `ValueError` for only one of `low_limit` and
  `high_limit`, a low limit above the high one, or a limit past 4194303, where
  one limit used to send a request for every device (#1483). ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- **Breaking (wire):** a Who-Has carrying only one of its two limits, or a
  low limit above the high one, is malformed: `WhoHasRequest::decode` refuses
  it and the server drops it unanswered, as it does such a Who-Is (#1483). ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- **Breaking (wire, Rust API):** every object that reports intrinsically
  classes the event rows its table requires for that as required, so
  ReadPropertyMultiple with REQUIRED returns them and the PICS lists them as
  required; the rows the tables only permit stay optional (#1485). ([d63feb9](https://github.com/jscott3201/rusty-bacnet/commit/d63feb908613f0550d858a19bef70a25ebc67796))

- **Breaking (wire, Python API, Rust API):** an Accumulator serves Scale and
  Prescale in their context-tagged Clause 21 forms, Python reads them as a
  float or int and a `(multiplier, modulo_divide)` pair that
  `add_accumulator` now takes, and Rust reads them as `ApplicationData`
  (#1487). ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Wire:** `BACnetRouter` neither forwards nor delivers a remote or global
  broadcast whose APDU isn't an Unconfirmed-Request, and `NetworkLayer` doesn't
  deliver one; both count it in the new `broadcast_pdu_type_drops()` (#1491). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Wire:** Linux Ethernet drops a frame whose source MAC is a group address
  before answering an XID or TEST command or decoding it, and counts it in the
  new `EthernetTransport::group_source_drops()` (#1492). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Wire:** Ethernet counts every multicast MAC, not only the all-ones
  broadcast, as a group destination, so a confirmed request to one is refused;
  `ethernet::is_group_mac` tells them apart (#1493). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Wire:** B/IP drops a Forwarded-NPDU whose originating address is a group
  address, so a forged I-Am can't bind a device to a group. B/IP and B/IPv6,
  which already dropped multicast origins, count such drops in the new
  `forwarded_group_origin_drops()` (#1493). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Wire:** The confirmed requests the server starts (events, Channel, Command,
  audit) never go to a group address such as a multicast one, and an I-Am from
  one binds nothing. A confirmed event recipient there counts in
  `confirmed_broadcast_recipient`; an unconfirmed one is still sent (#1493). ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Python API:** `PropertyValue.list` raises `ValueError` past 32 levels of
  nesting, pickles included, instead of crashing the process on a deep list,
  and `PropertyValue.real(0.0)` and `real(-0.0)`, equal already, now hash
  alike, as do `double` zeros (#1506). ([c4dc262](https://github.com/jscott3201/rusty-bacnet/commit/c4dc26269fdd21d184475bf3edb52e6df16b2be1))

- Analog and Binary Values carry independently optional Audit policy
  properties, set at creation in Rust and Python, which filter target Audit
  records.

### Security

- One event notification is forwarded to at most 64 destinations across all
  Notification Forwarders, and a retransmitted ConfirmedEventNotification is
  not forwarded again (#1259). ([76b2b84](https://github.com/jscott3201/rusty-bacnet/commit/76b2b84f0d75ce1d0d2b7a17713c10dbfaf5a945))

### Migration notes

- **Audit queries (#345):** Rust callers pass
  `BACnetSuccessFilter::{ALL, SUCCESSES_ONLY, FAILURES_ONLY}` and
  `Option<u64>` cursors. Python callers pass `successful_actions_only` as 0, 1
  or 2 instead of a bool: 1 for the old `True` and 0 for the old `False`.

- **SC TLS (Rust API, #513):** build hub TLS with `ScHubTlsConfig::from_der`
  for `ScHub::start`, and node TLS with `ScNodeTlsConfig` for
  `TlsWebSocket::connect` and the builders' `tls_config`, from owned CA, chain
  and key DER. See the [hub](docs/rust-api.md#bacnetsc-hub) and
  [node](docs/rust-api.md#strict-local-node-tls-configuration) migration
  notes.

- **SC device UUID (#517):** pass a nonzero 16-byte UUID to the `ScHub`
  startup APIs, `ScServerBuilder::device_uuid` and
  `ScTransport::with_device_uuid`, or `sc_device_uuid` and `device_uuid` in
  Python. Generate it before deployment, store it durably and reuse it; see
  the [Python](docs/python-api.md#sc-device-uuid-migration) and
  [Rust](docs/rust-api.md#sc-device-uuid-migration) migration notes.

- **DCC policy (Rust API, #522):** exhaustive `ServerConfig` literals need
  `dcc_disable_rate_limit: None` and `dcc_source_restriction: None`.

- **Custom transports (Rust API, #693):** implement
  `local_receive_apdu_capacity()`, the largest APDU the link accepts, and
  rename `max_apdu_length()` to `egress_apdu_limit()`; a wrapping transport
  delegates both. A `ReceivedNpdu` literal sets
  `provenance: TransportProvenance::unverified()` and `direct_response: None`.
  See [local receive capacity](docs/rust-api.md#local-receive-capacity-and-outgoing-limits). ([df016bb](https://github.com/jscott3201/rusty-bacnet/commit/df016bb551d99c88bd42b96cb6bca8ec75651045))

- **ObjectDatabase (Rust API, #728):** `ObjectDatabase::remove` returns
  `Result`.

- **Intrinsic reporting (Rust API, #746):** custom objects implement the
  evaluate and tick proposal hooks and `commit_event_transition_internal`
  instead of using `impl_intrinsic_reporting!` and
  `intrinsic_reporting_requires_atomic_commit`.

- **LifeSafetyOperation (Rust API, #752):** custom objects return
  `LifeSafetyOperationOutcome` from `apply_life_safety_operation`, listing the
  properties they changed for COV, and drop the `_detailed` hook.

- **Command sources (#824):** Rust local writes take a `LocalCommandSource`,
  and Python local writes the keyword `source_object`. `write_property_from`
  carries a network source, and the unsourced Analog Value setter is gone.

- **ObjectIdentifier (#847):** replace `ObjectIdentifier::new_unchecked` with
  `new` or `new_addressable`. Python raises `ValueError` for an oversized
  object type.

- **Builders (Rust API, #873):** replace `BACnetClient::builder()` and
  `BACnetServer::builder()` with `bip_builder()`.

- **Colour property identifiers (#887, Rust and Python API):** the
  `PropertyIdentifier` constants `DEFAULT_COLOR`, `DEFAULT_COLOR_TEMPERATURE` and
  `COLOR_COMMAND` keep their names but change value, to 4194330, 4194331 and 4194334
  (in Python, `PropertyIdentifier.COLOR_COMMAND.to_raw()` was 508). Use the
  constants, not 508 to 510, which name Network Port properties. ([97baf49](https://github.com/jscott3201/rusty-bacnet/commit/97baf4921afafc2ae9018a0dd68706de4e879bcd))

- **Parameter structs (Rust API, #902):** build
  `AnyTransport::Bip(Box::new(..))`, pass a `CovPropertySubscription` to
  `subscribe_cov_property` and a `RoutedTarget` to
  `send_apdu_routed_with_data_attributes`.

- **VT, WriteGroup and device identity services (#912):** `VTOpenRequest`
  needs a local session ID and a `VTClass`, WriteGroup takes `u16` channels
  and a `NonZeroU32` group number, and `WhoAmIRequest` the vendor ID, model
  name and serial number. Python's `vt_open`, `write_group` and `who_am_i`
  take the same. ([5ffc8a1](https://github.com/jscott3201/rusty-bacnet/commit/5ffc8a1a00c718762246839cba088b8c813d7f6e))

- **Typed alarm values (#914, #930, #932):** replace raw integers with the
  `bacnet-types` enumerations (`EventState`, `Reliability`, `LifeSafetyState`
  and so on) and bit strings (`StatusFlags`, `EventTransitionBits`,
  `DaysOfWeek`), and the objects' `LimitEnable` with
  `bacnet_types::bitstring::LimitEnable`. Python's `acknowledge_alarm`,
  `add_event_enrollment` and `get_enrollment_summary` take enum values. ([ca35afc](https://github.com/jscott3201/rusty-bacnet/commit/ca35afcde79727fce0176fc562e280d93134904d))

- **Wildcard BBMD (#952, #937):** a B/IP BBMD bound to `0.0.0.0` fails
  `start()` unless exactly one BDT row names a local address at the bound port
  or the default-route address is usable, and a loaded persisted BDT decides
  alone. Bind the interface address to avoid this; see the
  [BBMD section](docs/rust-api.md#bbmd).

- **Transport accessors (Rust API, #956):** add an
  `Error::UnsupportedTransport` arm to exhaustive matches. Read SC link state
  with `connection_state_changes()` instead of `ScTransport::connection()`,
  and MS/TP counts with `diagnostics()` instead of `node_state()`. ([5e9e676](https://github.com/jscott3201/rusty-bacnet/commit/5e9e6763b3224ff7dfc2e19ad7a6c9a132587a3a))

- **Schedule codecs (Rust API, #996):** import the calendar and schedule
  codecs from `bacnet_encoding::constructed`; `bacnet_services::schedule` and
  `BACnetDateRange::encode` and `decode` are gone. ([107e9fa](https://github.com/jscott3201/rusty-bacnet/commit/107e9fa5fe54d0c990083ac264b833b06672833f))

- **Python panics (#1002):** a Rust panic in an async method now raises PyO3's
  `PanicException` instead of `pyo3_async_runtimes.RustPanic`. It derives from
  `BaseException`, so `except Exception` no longer catches it. ([52bfdeb](https://github.com/jscott3201/rusty-bacnet/commit/52bfdeb3b6a76c2b953ff8bbfe7a7155ceb76dad))

- **Calendar and Schedule (Rust API, #1029, #845):** Calendar's
  `set_present_value` is gone and `add_date_entry` returns `Result`.
  `BACnetTimeValue::value` is a primitive `PropertyValue`. `tick_schedule`
  takes the date, the time and a Calendar resolver, not the weekday, hour and
  minute, and returns `Option<ScheduleWrite>`, whose `references` keep their
  array index, not a value with `(ObjectIdentifier, u32)` pairs. The Schedule
  setters and the `bacnet-encoding` schedule encoders return `Result`. ([5dc2537](https://github.com/jscott3201/rusty-bacnet/commit/5dc2537d6cd70588f76f74e85bfd459c94cf1f55))

- **Structured errors (Rust API, #1047, #1048):** `Error` gains
  `Structured { class, code, detail }`, and `TsmResponse::Error` gains
  `detail`. Some list-write refusals now return `Error::Structured` where they
  returned `Error::Protocol`, so match both for the class and code. ([0f43456](https://github.com/jscott3201/rusty-bacnet/commit/0f43456afa2ae49d066aa2875d2db1524e0e4966))

- **Access Credential and Access Door (Rust API, #1073, #979):**
  Credential_Status is read-only now; raise disable reasons with
  `add_disable_reason`. Set Assigned_Access_Rights and Authentication_Factors
  with `set_assigned_access_rights` and `set_authentication_factors`, and
  build `BACnetAssignedAccessRights` with a `BACnetDeviceObjectReference`.
  `AccessDoorObject::set_relinquish_default` takes a `DoorValue`. ([42e4528](https://github.com/jscott3201/rusty-bacnet/commit/42e45288181d8fa383c5b41fce6de387bdb034a1))

- **Schedule references (Rust API, #1088):**
  `ScheduleObject::add_object_property_reference` returns `Result`. A wrapper
  that forwards every trait method needs the new `take_owed_schedule_writes`
  and `complete_schedule_write` hooks. ([7762130](https://github.com/jscott3201/rusty-bacnet/commit/77621307d247d88a91dcb0478a844ffd54bcf880))

- `RangeSpec` reference index and sequence, `ReadRangeAck::first_sequence_number`
  and `LogRecordIdentity::sequence_number` are now `u64`; widen any code that
  builds or matches them (#1092). ([e49a6f3](https://github.com/jscott3201/rusty-bacnet/commit/e49a6f35072009ee10dd2333a262039b41225c02))

- **Recipient_List (Rust API, #1098, #1125):** read the list with
  `recipient_list()`, since the field is private, and handle the `Result` from
  `add_destination`. A local write takes only the framed BACnetLIST in
  `PropertyValue::ApplicationData`; write empty application data to clear it. ([2caee31](https://github.com/jscott3201/rusty-bacnet/commit/2caee311979e4311fd7f87d4e09bee815dee50ac))

- **Global Group (Rust API, #1107):** `GlobalGroupObject::present_value` is a
  `Vec<AccessResult>` holding, by member position, the value or error each
  member's read produced. ([0980c10](https://github.com/jscott3201/rusty-bacnet/commit/0980c10774260915fc65845d99e8fa05b07fee5f))

- **`BACnetObject::cov_increment` returns `Option<f64>` (#1111):** an object
  that overrides it changes the signature and returns
  `Some(f64::from(increment))`; `CovSubscriptionTable::should_notify` takes
  an `Option<f64>` increment too. ([d81bcfa](https://github.com/jscott3201/rusty-bacnet/commit/d81bcfa04d6669bb474a8b0503e83ceecfcccee5))

- `BACnetShedLevel` percent and level hold `u64`, and
  `LoadControlObject::set_requested_shed_level` and `set_actual_shed_level`
  return `Result` (#1133). ([0debbca](https://github.com/jscott3201/rusty-bacnet/commit/0debbcadb03353f5b065c76b9207f97219248d33))

- **Group (Rust API, #1134):** `GroupObject::add_member` takes a
  `ReadAccessSpecification` and returns `Result`. `PropertyReference` and
  `ReadAccessSpecification` moved to `bacnet_types::constructed`, with their
  codecs in `bacnet_encoding::constructed`; update imports. ([9217089](https://github.com/jscott3201/rusty-bacnet/commit/9217089a8c6dd561c5dcb096738f3d58a8fb42c1))

- **Structured View and Command (Rust API, #1135):**
  `StructuredViewObject::subordinate_list` holds `BACnetDeviceObjectReference`
  values (an `ObjectIdentifier` still converts), and
  `CommandObject::set_action` takes `Vec<BACnetActionList>` and returns
  `Result`. ([b7f1209](https://github.com/jscott3201/rusty-bacnet/commit/b7f12093227a886113ca8d63eb6f488a65e185cb))

- **Reference setters (Rust API, #1182, #1234):** the Life Safety `add_member`
  and `add_zone_member` take a `BACnetDeviceObjectReference` (an
  `ObjectIdentifier` converts), and they, `set_log_device_object_property` and
  `add_property_reference` return `Result`; handle it. A single reference now
  reads as `PropertyValue::ApplicationData`, and the Trend Log Multiple array
  and Life Safety lists as a `List` of them. ([11c55eb](https://github.com/jscott3201/rusty-bacnet/commit/11c55eb65924f8de11ace8c20cf57f330dfbb451))

- `TrendLogMultipleObject::add_record` and `records()` use
  `BACnetLogMultipleRecord` (one `LogValue` per member) instead of
  `BACnetLogRecord`; object wrappers forward the new
  `BACnetObject::add_trend_multiple_record` hook (#1203). ([eb86197](https://github.com/jscott3201/rusty-bacnet/commit/eb8619781f2917baa381a61d65fd671dc76bf987))

- **Breaking:** `BACnetRouter::start` takes a `RouterOptions` and returns a
  `StartedRouter` (#1220). Replace `start(ports)` with
  `start(ports, RouterOptions::new())` and take `router` and `apdus` from the
  result. ([ff7ba6b](https://github.com/jscott3201/rusty-bacnet/commit/ff7ba6b9ad49359a00b46453334c83a8fd7dafb0))

- **ReceivedApdu (Rust API, #1225):** `bacnet_network::layer::ReceivedApdu` has a new
  `global_broadcast` field. Code that builds one with a struct literal adds
  `global_broadcast: false`, or `true` for an NPDU sent to DNET 65535. ([fafc1dd](https://github.com/jscott3201/rusty-bacnet/commit/fafc1ddf07b6f4171f219274d1e2b5ae5c08c529))

- `EventLogObject` stores `BACnetEventLogRecord`; log statuses are `LogStatus`, Trend Log
  `status_flags` is `Option<StatusFlags>`, and INTEGER/ENUMERATED log values are `i64`/`u64`.
  Read records through `records()` or ReadRange; wrappers forward `log_buffer_internal`, whose
  `encode_record` returns nothing (#1233, #1237). ([e1d1d0d](https://github.com/jscott3201/rusty-bacnet/commit/e1d1d0d35367438d4da43b1e6bf76e0240cf95af))

- 0.11.0 Audit Log snapshots are converted automatically on first load and saved as schema v3.
  The Python `log_status` int keeps 1 = log-disabled, 2 = buffer-purged, 4 = log-interrupted
  (#1233). ([e1d1d0d](https://github.com/jscott3201/rusty-bacnet/commit/e1d1d0d35367438d4da43b1e6bf76e0240cf95af))

- **Trend Log Multiple (Rust API, #1235):** `set_logging_type` takes a
  `LoggingType` and returns `Result`; handle the VALUE_OUT_OF_RANGE a COV
  value now gets. `TrendLogObject::set_logging_type` takes a `LoggingType`
  too. Object wrappers forward the new
  `BACnetObject::refresh_log_window_internal` hook. ([72c1770](https://github.com/jscott3201/rusty-bacnet/commit/72c17700434f51678eab44474bc41bbbe4e5f7e6))

- **Audit Log persistence (Rust API, #1270):** custom Audit Log persistence
  runs on a plain `std` thread with no Tokio context, and a panic there fails
  the save. ([1d3eb21](https://github.com/jscott3201/rusty-bacnet/commit/1d3eb211c7700a20b59320ddf968c4fe8c269744))

- **Server (wire, #1257):** the server no longer answers a confirmed request sent by broadcast or
  multicast. A client that relied on that must address the device directly, by unicast or a routed
  DNET/DADR. ([76b2b84](https://github.com/jscott3201/rusty-bacnet/commit/76b2b84f0d75ce1d0d2b7a17713c10dbfaf5a945))

- **Lighting Output Lighting_Command (#1263):** a read returns
  `PropertyValue::ApplicationData` (Python `application_data`) holding the encoded
  command, and a write takes that encoding instead of an octet string. Build it with
  `bacnet_encoding::constructed::encode_lighting_command`, or set it with
  `LightingOutputObject::set_lighting_command`. A new object reads operation NONE,
  which can't be written back. ([91ce62a](https://github.com/jscott3201/rusty-bacnet/commit/91ce62a13f533db07b8a6c5586c2facf75edeb03))

- **Event notification codecs (Rust API, #1276):** `EventNotificationRequest`,
  `NotificationParameters` and `BACnetPropertyValue` lose their `encode` and
  `decode` methods; call `encode_event_notification`,
  `decode_event_notification`, `encode_notification_parameters`,
  `decode_notification_parameters`, `encode_bacnet_property_value` or
  `decode_bacnet_property_value` in `bacnet_encoding::constructed`. Build an
  Event Log notification record from the typed request, not its bytes. ([ea05d58](https://github.com/jscott3201/rusty-bacnet/commit/ea05d5890885085fd54f7e3e3f6a0d186434fda2))

- **Structured View (Rust API, #1285):**
  `StructuredViewObject::add_subordinate` returns `Result`, and the Structured
  View subordinate fields are private: replace them with `set_subordinates`
  and read them with `subordinates()`. ([9cd82bc](https://github.com/jscott3201/rusty-bacnet/commit/9cd82bc9c4126d5fa0953099a9fa5fdd898e52c2))

- **Python reads and local writes (#1296, #1297):** a whole array or list (such
  as Object_List or Priority_Array) is a `list` even with one element, a
  constructed value is `application_data` bytes unless it is one of the typed
  reads listed under #1310, #1344 and #1345, and an empty value is
  `PropertyValue.list([])`. `BACnetServer.read_property` and
  `write_property_local` raise `BacnetProtocolError` as network requests do: a
  missing object is UNKNOWN_OBJECT, not `RuntimeError`. ([ce572cf](https://github.com/jscott3201/rusty-bacnet/commit/ce572cf812e35750d255bfc885eb5ebdfe364548))

- **Device reference setters (Rust API, #1308):**
  `EventEnrollmentObject::set_object_property_reference` returns `Result`;
  `GlobalGroupObject::group_members` is private, so set it with
  `set_group_members` or `add_group_member` (both `Result`) and read it with
  `group_members()`. ([7ade5e3](https://github.com/jscott3201/rusty-bacnet/commit/7ade5e36df847e9d7909ff6d4b9d7615824cd0f4))

- **Python typed reads (#1310):** Recipient_List, List_Of_Group_Members,
  Group Present_Value, Action, Door_Members, Access_Doors, Target_References,
  Supported_Formats and Stages read as typed elements in the typed write's
  form. A 0.11.0 local read gave the stored form (`application_data` octets
  for Recipient_List, a flat list for the others) and a client read only the
  first application-tagged value; compare against the typed form. Writing
  back is unchanged. ([e04ef28](https://github.com/jscott3201/rusty-bacnet/commit/e04ef2883cafe4f8b1a3958a3b5395928723a183))

- **Loop and Pulse Converter references (#1312):** a read returns
  `PropertyValue::ApplicationData` (Python `application_data`) holding the encoded
  reference, and a write takes that encoding; decode it with
  `bacnet_encoding::constructed::decode_object_property_reference`, or
  `decode_setpoint_reference` for Setpoint_Reference. Clear a reference by writing
  one to instance 4194303, or Setpoint_Reference with the empty value; Null changes
  nothing, and an empty [0] frame or unframed members are refused. ([808e0c2](https://github.com/jscott3201/rusty-bacnet/commit/808e0c2903b79898c17009d9f583c1986c248fe0))

- **Access Rights (Rust API, #1316):** `BACnetAccessRule` takes the Clause 21
  shape: the specifiers are `AccessRuleTimeRangeSpecifier` and
  `AccessRuleLocationSpecifier`, and the time range is a
  `BACnetDeviceObjectPropertyReference`. `BACnetAccessRule::new` builds one
  from optional references. ([2323bf7](https://github.com/jscott3201/rusty-bacnet/commit/2323bf7cfd07a888ebf64c1272cec84657c1e642))

- Code that matched `CovAckResult::Error` matches `CovAckResult::Error(_)`, or binds the `Refusal` to read what the peer answered (#1323). ([0863c0f](https://github.com/jscott3201/rusty-bacnet/commit/0863c0f590582684016b70b3ff1f89442509b2a5))

- **Event_Algorithm_Inhibit (Rust API, #1329):** `BACnetObject` gains the
  hidden hooks `event_algorithm_inhibit_reference_internal` and
  `follow_event_algorithm_inhibit_internal`, and `ObjectDatabase` gains
  `follow_event_algorithm_inhibit`, which the bundled server calls before it
  evaluates an object. A wrapper object that forwards its hooks forwards
  both; a custom intrinsic reporter can serve the rows by answering them. ([d63feb9](https://github.com/jscott3201/rusty-bacnet/commit/d63feb908613f0550d858a19bef70a25ebc67796))

- **Confirmed answers (Rust API, #1342):** `bacnet_server::server::CovAckResult`
  has a `Data(Bytes)` variant, the service data of a ComplexAck answering a
  read the server sent, and is no longer `Copy`; add an arm for it where you
  match the enum, and clone where you copied it. ([cbe62f3](https://github.com/jscott3201/rusty-bacnet/commit/cbe62f311b478671b7cafadb789affb2fbf238c9))

- **Python typed access reads (#1344):** compare reads of Entry_Points,
  Exit_Points and Credentials with `ObjectIdentifier` or `(device, object)`
  values tagged `device_object_reference`, not 0.11.0's plain object
  identifiers; writing a read value back is unchanged. ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Python typed constructed reads (#1345):** reads of the properties in
  [the typed constructed values table](docs/python-api.md#typed-constructed-values)
  return the forms it gives (mappings, tuples, `BACnetTimeStamp`) instead of
  0.11.0's octets or flat lists, so a read that gave
  `PropertyValue.application_data` no longer equals it; writing a read value
  back sends the same octets. ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Trend Log (Rust API, #1354):** `TrendLogObject::set_logging_type`
  returns `Result`; handle the OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED a COV
  value gets until COV acquisition lands (#1480). To stop a polled Trend Log,
  clear Enable or make it TRIGGERED: writing its Log_Interval from nonzero to
  zero is refused the same way. ([1be8248](https://github.com/jscott3201/rusty-bacnet/commit/1be824832f0d675a17f3f3cf9846eb230287c57b))

- **Python integer range errors (#1360):** any integer argument outside the
  type of the field it fills raises `OverflowError`, as a parameter, a tuple
  member or a mapping value; catch it where you caught `ValueError` or
  `BacnetProtocolError` for, say, `BACnetTimeStamp.sequence_number(65536)`, a
  Destination `process_identifier` past 2**32 - 1, a channel number past
  65535 or a mapping's negative array index. Values that fit but BACnet
  refuses still raise `ValueError` or `BacnetProtocolError`. ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Local writes (Rust API, #1367):** await `write_local`, `write_local_encoded` and the `*_local`
  setters inside a Tokio runtime. Polled by another executor, they now fail with `Error::Encoding`
  before anything is written. ([aef70c4](https://github.com/jscott3201/rusty-bacnet/commit/aef70c43149af99d5c3dcc3d36d5ccc3313f7eb1))

- **bacnet-encoding (Rust API, #1374):** `tags::decode_optional_context` is
  removed. Peek with `constructed::tagged::next_is_context`, then read the
  member with `decode_ctx_primitive` or a typed reader, or wrap one in
  `decode_optional_ctx`. ([d682790](https://github.com/jscott3201/rusty-bacnet/commit/d68279070d0a21da717d84f10db7854b59a2f10b))

- **Color and Color Temperature Color_Command (#1386):** a read returns
  `PropertyValue::ApplicationData` holding the encoded command, and a write takes
  that encoding instead of an octet string. Build it with
  `bacnet_encoding::constructed::encode_color_command`, or set it with
  `set_color_command` on `ColorObject` or `ColorTemperatureObject`. A new object
  reads operation NONE, which can't be written back. ([97baf49](https://github.com/jscott3201/rusty-bacnet/commit/97baf4921afafc2ae9018a0dd68706de4e879bcd))

- **I-Am announcements under DCC (Rust API, #1388):**
  `BACnetServer::broadcast_i_am()` and `IAmBroadcaster::broadcast_i_am()`
  return `Error::Protocol` with `SERVICES` / `COMMUNICATION_DISABLED` while a
  remote DeviceCommunicationControl restricts initiation. An announce loop
  that unwraps the result must treat that error as a skipped announcement. ([cd9c650](https://github.com/jscott3201/rusty-bacnet/commit/cd9c650d1042f0aeb9501c94785e821a545a1dc3))

- **DCC state (Rust API, #1399):** `BACnetServer::comm_state()` returns
  `bacnet_server::server::DccState`. Compare with `DccState::Enable` or
  `DccState::DisableInitiation`, call `initiation_restricted()`, or take
  `EnableDisable::from(state).to_raw()` where the old 0 or 2 is needed; that
  is a `u32`, where the old getter returned a `u8`. ([e9472a8](https://github.com/jscott3201/rusty-bacnet/commit/e9472a845f846dbb32285fdfbbc8e352d59dcac5))

- **Server drop (Rust API, #1270, #1409):** durable saves now finish on a writer thread, so storage
  may still change after a `BACnetServer` dropped without `stop()` is gone. Call `stop().await`
  before dropping a server and building another on the same storage. ([9a24975](https://github.com/jscott3201/rusty-bacnet/commit/9a24975c693bb99f132fedcf73fe8474cbbb8263))

- **Unset references (wire and Python API, #1417):** Controlled_Variable_Reference,
  Manipulated_Variable_Reference, Input_Reference, a Trend Log's
  Log_DeviceObjectProperty and Object_Property_Reference no longer read NULL
  while unset. Treat a reference whose object or Device instance is 4194303 as
  unset, and clear one by writing such a reference, not NULL; clear
  Fault_Parameters with its context-tagged `none` choice. ([5555911](https://github.com/jscott3201/rusty-bacnet/commit/55559112ff4daadbb7570f8c29d3839ab53750a2))

- **DCC handler (Rust API, #1430):**
  `bacnet_server::handlers::handle_device_communication_control` is removed.
  Let a `BACnetServer` answer DeviceCommunicationControl under its `DccPolicy`
  and `dcc_password`, and read the state with `BACnetServer::comm_state()`, a
  `DccState`. A custom dispatcher decodes the request with
  `bacnet_services::device_mgmt::DeviceCommunicationControlRequest::decode`
  and applies its own checks. ([eeb9dd9](https://github.com/jscott3201/rusty-bacnet/commit/eeb9dd9c7fe2f666423d82a378a42592352367f1))

- **DCC state (Python API, #1431):** compare `await server.comm_state()` with
  `EnableDisable.ENABLE` or `EnableDisable.DISABLE_INITIATION`. The result
  never equals 0 or 2 and is truthy in both states, so
  `if await server.comm_state():` no longer tells them apart. Call
  `.to_raw()` where the number is needed. ([eeb9dd9](https://github.com/jscott3201/rusty-bacnet/commit/eeb9dd9c7fe2f666423d82a378a42592352367f1))

- **Multi-state objects (Rust API, #1443):** Number_Of_States rows carry the
  new `PropertyWriteCapability::Through(STATE_TEXT)`, which doesn't count as
  writable; the PICS row carries `PropertySupport::written_through`. ([d63feb9](https://github.com/jscott3201/rusty-bacnet/commit/d63feb908613f0550d858a19bef70a25ebc67796))

- **Decoding errors (Rust API, #1446):** add `..` to patterns on
  `Error::Decoding { offset, message }`, or bind `kind`, and build one with
  `Error::decoding` or a kind's constructor (`invalid_tag`, `missing`,
  `trailing`, `out_of_range`, `overflow`) rather than a struct literal. Match
  `kind: DecodingKind::InvalidTag` where you matched `Error::InvalidTag`, and
  turn a request's decode error into its Reject with
  `Error::into_request_reject`. ([d54b143](https://github.com/jscott3201/rusty-bacnet/commit/d54b143114dbc71de28731df2362893a34824393))

- **Answer matching (Rust API, #1465):** `CanonicalPeer::from_source` takes the
  known local network number as a third argument (`None` keeps the old
  matching). ([520abe7](https://github.com/jscott3201/rusty-bacnet/commit/520abe781edc7613dfb2a38e0c8a20e2b31d6cdd))

- **Broadcast sends (Rust API, #1479):** send a remote network's broadcast
  with `NetworkLayer::broadcast_to_network`, not
  `send_apdu_routed_via_local_broadcast` with an empty `dest_mac`. Send a
  confirmed request, an acknowledgement, an Error, a Reject or an Abort to
  one device: the broadcast sends and a routed send with no DADR refuse it,
  and so do confirmed requests from `BACnetClient`, the endpoint and Python
  to any group address, all before anything is sent. ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- **Who-Is and Who-Has ranges (Rust API, #1483):** `WhoIsRequest::range(low,
  high)` is gone. Write `range: None` or
  `range: Some(DeviceInstanceRange::new(low, high)?)` in `WhoIsRequest` and
  `WhoHasRequest`, and pass that one value to `BACnetClient::who_is`,
  `who_is_directed`, `who_is_network` and `who_has`. `single(n)` and
  `from_limits` return a `Result`; `device(oid)` cannot fail. Python callers
  pass both limits or neither. ([5906270](https://github.com/jscott3201/rusty-bacnet/commit/5906270d083661dee9943b7c7302a5875533e1dd))

- **Property metadata (Rust API, #1485):**
  `PropertyPresenceCondition::IntrinsicReporting` is split into
  `IntrinsicReportingRequired`, which `PropertyMetadata::is_required` counts,
  and `IntrinsicReportingOptional`; a custom object's rows pick the one its
  table's footnotes give. ([d63feb9](https://github.com/jscott3201/rusty-bacnet/commit/d63feb908613f0550d858a19bef70a25ebc67796))

- **Accumulator Scale and Prescale (#1487):** a client decoding the old
  application-tagged Scale or Prescale decodes the context-tagged forms
  instead. In Python, Scale's tag is `"scale"`, not `"real"`, and Prescale
  reads as `(5, 100)`, not `[5, 100]`. In Rust, `read_property` returns
  `PropertyValue::ApplicationData`, not a `List`; decode it with
  `bacnet_encoding::constructed::{decode_scale, decode_prescale}`. ([b352d84](https://github.com/jscott3201/rusty-bacnet/commit/b352d8488073935271ce2b62a9f21029b6c211f5))

- **Device bindings (Rust and Python API, #1493):** a binding at a multicast
  address, 255.255.255.255 or the broadcast IP at another port, as the
  device's own address or its router's, now stops `build()` and `start()`.
  Bind each device, or its router, at its unicast address. ([df0f8b8](https://github.com/jscott3201/rusty-bacnet/commit/df0f8b878577ae71b68ce52ea860bf7be1deeb33))

- **Dates (Python API, #1501):** a `"date"` value's `.value` gives the full
  year, so drop any `+ 1900` applied to it; an unspecified year still reads
  as 255, `rusty_bacnet.UNSPECIFIED`. `PropertyValue.date` takes 1900 to 2154
  or 255. `time_synchronization` and `utc_time_synchronization` need a real
  date with its own weekday and a time with no field unspecified. ([17404bb](https://github.com/jscott3201/rusty-bacnet/commit/17404bb55178e00727f2431bc2ccbc44a87599ad))

- **DCC password (Rust and Python API):** a password alone no longer enables
  DeviceCommunicationControl. Select `RequirePassword` (`"require_password"`)
  with a password, or the **insecure** `LegacyPermissive` mode; exhaustive
  `ServerConfig` literals need `dcc_policy`. See
  [DCC policy](docs/dcc-policy.md).

- **Request encoders (Rust API, #771, #780, #793, #798, #805, #808):** the
  ReadRange, ReadPropertyMultiple, WriteProperty, WritePropertyMultiple,
  AddListElement, RemoveListElement, SubscribeCOV and
  SubscribeCOVPropertyMultiple request encoders return `Result`; handle the
  error where you call one directly.

- **Request admission (Rust and Python API):** exhaustive `ServerConfig`
  literals and patterns need the new fields; see
  [request admission](docs/request-admission.md).

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
