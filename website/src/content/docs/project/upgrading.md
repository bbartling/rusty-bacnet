---
title: "Upgrade from v0.11.0 to v0.12.0"
description: "Review the breaking changes by area before replacing a working integration."
---

Do not treat this pre-1.0 update as a drop-in replacement merely because the package name stayed the same. v0.12.0 changes Rust and Python APIs, some on-the-wire behavior, BACnet/SC trust and identity, and how several objects answer. This page groups the changes that need action. The [0.12.0 section of the changelog](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/CHANGELOG.md) is the full list, including fixes and additions that need no action; its migration notes give the exact replacements.

## Before updating

Record your current package/binary version, enabled features, platform, transport, and important application workflows. Back up persisted Audit Log snapshots and Notification Forwarder files before the first start on v0.12.0. Keep a known-working deployment or environment available according to your operational policy.

## Update the selected interface

In a Python virtual environment:

```sh
python -m pip install --upgrade rusty-bacnet==0.12.0
```

For Rust, move every `bacnet-*` dependency to `0.12.0` together; all eleven crates share the version, and `bacnet-endpoint` and `bacnet-cli` are new on crates.io. For the CLI, [download the v0.12.0 executable](/rusty-bacnet/start/installation/#install-a-cli-executable), check it against `SHA256SUMS`, and confirm its version and features.

The packaging changed too:

- The Linux CLI executables need glibc 2.17 or newer and no libpcap package; v0.11.0's needed glibc 2.39 and libpcap. The Windows executable no longer needs the Visual C++ Redistributable.
- Wheels now cover CPython 3.11 to 3.14, and every wheel includes MS/TP.

## Rust API

- `BACnetClient::builder()` and `BACnetServer::builder()` are gone; use `bip_builder()`. `NetworkNumber` moved to `bacnet_types::network_number` without an alias, and `ObjectIdentifier::new_unchecked` gave way to the validating `new` and `new_addressable` (#847, #873, #879).
- `Error::ChangeList` became `Error::Structured`, which the client now returns for every structured error body. `Error::Decoding` carries a `DecodingKind`, `Error::InvalidTag` is gone, and matches need an `Error::UnsupportedTransport` arm (#956, #1026, #1047, #1048, #1446).
- Long argument lists became structs such as `CovPropertySubscription`, `RoutedTarget` and `WritePropertyRequest`, and `AnyTransport::Bip` holds a `Box` (#902).
- Constructed-value codecs are free functions in `bacnet_encoding::constructed`, with their types in `bacnet_types::constructed`. The request, recipient and schedule encoders return `Result`, and `bacnet_services::schedule` and `tags::decode_optional_context` are gone (#771, #793, #996, #1134, #1156, #1276, #1374).
- Alarm and event types use the `bacnet-types` enumerations and bit strings, such as `EventState` and `StatusFlags`, instead of raw integers (#914, #930, #932).
- Who-Is and Who-Has take one optional `DeviceInstanceRange` instead of two limits. The VT-Open, WriteGroup and Who-Am-I requests carry their standard fields (#912, #1483).
- Single-property COV subscriptions take a `NonZeroU32` lifetime. Audit queries take a `BACnetSuccessFilter` and `u64` cursors, and ReadRange sequence numbers are `u64` (#345, #802, #1092).
- Struct literals of the counters, `SessionConfig`, `ServerConfig`, `ReceivedApdu` and `ScheduleWrite` need the new fields or `..`; `DiscoveryCounters` is `#[non_exhaustive]` (#522, #1066, #1158, #1196, #1225, #1346, #1436, #1493).
- `CanonicalPeer::from_source` and the admission helpers take the local network number (`None` keeps the old matching), and `admit_notification_terminal` is gone (#1465).
- The PICS generator's `CharacterSet` renames or drops four variants to match the six standard character sets (#913).

## Python API

- A Rust panic raises `PanicException`, which `except Exception` misses. A transport failure raises `BacnetTransportError`, which is also an `OSError` (#1002, #1120).
- Native methods return futures typed `Awaitable`; await them or wrap them with `asyncio.ensure_future`, not `create_task` (#858).
- An integer outside its field's range raises `OverflowError` everywhere, and an oversized object type raises `ValueError` (#847, #1360).
- An array or list reads as a `list` at any length. Local `read_property` and `write_property_local` behave like network requests and raise `BacnetProtocolError` (#1296, #1297).
- Constructed properties read as typed mappings, tuples and objects instead of `application_data` octets, so comparisons against octets change. Writing a read value back still works (#1310, #1344, #1345, #1487).
- Dates carry the full year, so drop any `+ 1900`; an unspecified year is 255, `rusty_bacnet.UNSPECIFIED`. `time_synchronization` and `utc_time_synchronization` need a specific date and time (#1501).
- `ObjectIdentifier`, `PropertyValue` and `BACnetTimeStamp` support copying and pickling, and every exported class belongs to the `rusty_bacnet` module (#1500).
- `comm_state()` returns `EnableDisable` values, which are all truthy; compare with them or call `.to_raw()` (#1431).
- `successful_actions_only` takes 0, 1 or 2 (1 for the old `True`), and the alarm calls take enum values. Who-Is limits come in pairs, and local writes take `source_object` (#345, #824, #912, #914, #1483).
- `configure_audit_recipient` replaces `recipient_device_instance`, `configure_audit_reporters` replaces the single Reporter settings, and `add_bip_network_port` replaces raw Network Port construction (#728, #782, #867).

## Wire behavior

- The server ignores a confirmed request sent by broadcast or multicast, and the stack won't send one to a group address. Address each device by unicast or a routed DNET/DADR (#1257, #1479, #1493).
- An undecodable confirmed request draws a Reject naming the fault, and trailing octets or wrongly tagged members are refused (#1374, #1375, #1411, #1446).
- A Who-Is or Who-Has carrying only one range limit is dropped (#1447, #1483).
- AddListElement and RemoveListElement errors name the first failed element; duplicates are skipped and a missing element fails the whole removal. CreateObject and SubscribeCOVPropertyMultiple errors carry their full bodies (#1026, #1027, #1047, #1048).
- ReadRange reads only lists. SubscribeCOVPropertyMultiple stops at the first failing reference, and a zero COV lifetime is refused (#802, #1025, #1058, #1059, #1102).
- Priority_Array is read-only; command and relinquish through Present_Value with a priority (#842).
- Default_Color, Default_Color_Temperature and Color_Command use their standard property identifiers instead of 508 to 510, which belong to Network Port; use the named constants (#887).
- Who-Am-I, You-Are, VT and WriteGroup encode in the standard form (#912).
- Addresses longer than 18 octets are refused by the codecs, recipients and the DCC, time-sync and COV-policy lists (#1098, #1156, #1157, #1199, #1200, #1266).
- While DCC disables initiation, the server skips I-Have and `broadcast_i_am()` returns an error; Who-Is still gets an I-Am (#1388).
- Notifications to a recipient on the local network number go out as local traffic (#1299).

## CLI

- `bacnet --sc` requires `--sc-ca` with the site CA and no longer loads the system roots (#513). See [BACnet/SC](/rusty-bacnet/guides/bacnet-sc/).
- `bacnet read-range` decodes log records, and its JSON lists them under `records` instead of `items` (#1274).
- The Docker test tools in `benchmarks/` changed too: `bacnet-sc-hub` requires `--ca`, `--cert`, `--key` and `--device-uuid`, and `bacnet-device --transport=sc` needs SC credentials and a device UUID (#513, #517).

## Transports

- BACnet/SC needs mutual TLS 1.3 with explicit CA trust. Build `ScHubTlsConfig` and `ScNodeTlsConfig` from DER, or pass `sc_ca_cert`, `sc_client_cert` and `sc_client_key` (and `ca_cert` for `ScHub`) in Python (#513).
- Every SC hub and node needs a nonzero device UUID (`sc_device_uuid` in Python). Provision it once and keep it for the device's life (#517).
- One SC hub relay send budget covers all traffic, set with `with_relay_send_budget` or `relay_send_budget_ms` (#476, #774).
- Read SC link state with `connection_state_changes()` and MS/TP counts with `diagnostics()`. An SC hub bind failure is `Error::Transport` (#956, #1104).
- B/IPv6 with `::` or no interface selects one unambiguous local link and address, and fails startup when the choice is ambiguous; pass a concrete address. v0.11.0 fell back to a wildcard bind.
- A B/IP BBMD bound to `0.0.0.0` fails `start()` when it can't tell its own address; bind the interface address instead (#937, #952).
- A device or router binding at a multicast or broadcast address fails `build()` and `start()`. B/IP drops forwarded packets from a group origin (#1493).
- `BACnetRouter::start` takes `RouterOptions` and returns a `StartedRouter` (#1220).
- Use `broadcast_to_network` for a remote broadcast. Routed confirmed requests refuse DNET 0, DNET 65535 and an empty DADR (#1267, #1278, #1479).
- NPDUs and frames with addresses over 18 octets are dropped and counted, and router rejects go back to the original sender (#1141, #1158, #1198).
- A NORMAL B/IP Network Port follows its real bind, replacing `sync_bip_bind` and raw Network Port construction (#863, #867).

## Objects and server

- Objects serve the properties their standard tables list. Undefined rows, such as Out_Of_Service on Command, answer UNKNOWN_PROPERTY, and missing required rows appear; regenerate your PICS (#979, #985, #1021, #1052, #1062, #1064, #1073, #1092, #1227, #1284, #1485).
- Constructed properties, from Lighting_Command and Color_Command to references and schedules, use their standard encodings and refuse the old octets. Rust reads them as `ApplicationData`; use the `bacnet_encoding::constructed` helpers (#980, #996, #1107, #1133, #1134, #1169, #1234, #1312, #1386, #1395, #1487).
- An indexed array read returns one element, or UNKNOWN_PROPERTY for an array the object lacks. An unset reference reads as instance 4194303, not NULL; write such a reference to clear it (#1034, #1296, #1417, #1426).
- Many setters validate and return `Result`, take typed values, or sit behind accessors such as `recipient_list()`. Device references refuse non-Device identifiers (#1029, #1087, #1088, #1098, #1149, #1182, #1249, #1285, #1308, #1316).
- Custom objects and wrappers adopt the reworked `BACnetObject` hooks for intrinsic reporting, life safety, COV increment, schedules, logs and Audit Reporters; `impl_intrinsic_reporting!` is gone (#746, #815, #845, #889, #1088, #1111, #1203, #1233, #1329, #1433, #1436).
- The server refuses DeviceCommunicationControl, even with the right password, until you pick a `DccPolicy` (`dcc_policy` in Python). `comm_state()` returns a `DccState`, and request admission's confirmed peer ceiling splits into ordinary and recovery quotas (#522, #1399, #1430).
- `CovRecipient` replaces `MultipleRecipient` and `CovPeerKey`, and `CovPolicy::validate` refuses zero caps. `CovAckResult` gains `Error(Refusal)` and `Data` (#810, #817, #826, #833, #840, #986, #1100, #1323, #1342).
- Local writes take a `LocalCommandSource`. Command and Channel write members in other devices, and the mutation authorizer decides WriteGroup writes (#824, #1150, #1180, #1264, #1319).
- The server executes and forwards received event notifications, and Recipient_List holds at most 32 destinations. The Audit recipient is set on the built-in Device, and target auditing takes 1 to 64 Reporters (#728, #782, #783, #1098, #1124, #1125, #1225, #1259).
- Log_Buffer reads only through ReadRange, and the pollers log any datatype. Trend Logs refuse COV logging for now (#1480), so stop a polled log by clearing Enable (#1092, #1233, #1236, #1354).
- Calendar follows the local date, and a Schedule evaluates in the standard order. A target that refuses its write sets the Schedule's Reliability to CONFIGURATION_ERROR (#1028, #1029, #1086, #1433).
- Access objects accept simulated writes while out of service and refuse NORMAL in their alarm values. A State_Text write sets Number_Of_States, and Averaging samples itself over a sliding window (#1083, #1131, #1144, #1149, #1247, #1401, #1443).

## Persistence

- Audit Log snapshots from v0.11.0 convert to the new schema on first load (#1233). Keep the backup until the converted log checks out.
- Forwarder persistence is now `NotificationForwarderPersistence` and saves both lists; delete the old backend's files. A restored Recipient_List wins over configured destinations (#1256).
- Custom Audit Log and forwarder persistence runs on a plain thread with no Tokio context, and a panic fails the save (#1270).
- A wildcard BBMD with a persisted BDT finds its own address from that table alone (#952).

## Verify more than import success

Exercise a known read, error handling, any routing or segmentation paths you depend on, subscription lifecycle, relevant server objects, and controlled cleanup. SC and MS/TP deployments need transport-specific validation, not only package-level tests.

Retest your application's output parsing where it depends on CLI JSON, typed Python values or Rust models: constructed properties, dates and arrays read differently now. Separate regressions from corrected behavior that an older integration may have depended on accidentally. The [integration guides](/rusty-bacnet/development/overview/) explain shared endpoints, Network Port registration and SC setup, which are new or changed in this release.

## Sources and release scope

This guide covers the move from **v0.11.0** to **v0.12.0**. Source review is not hardware qualification.

[v0.12.0 release notes](https://github.com/jscott3201/rusty-bacnet/releases/tag/v0.12.0) · [Changelog](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/CHANGELOG.md) · [Rust API guide](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/docs/rust-api.md) · [Python API guide](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/docs/python-api.md).
