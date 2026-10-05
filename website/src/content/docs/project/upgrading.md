---
title: "Upgrade from v0.11.0 to v0.12.0"
description: "Review the breaking changes by area before replacing a working integration."
---

Do not treat this pre-1.0 update as a drop-in replacement merely because the package name stayed the same. v0.12.0 changes Rust and Python APIs, some on-the-wire behavior, BACnet/SC trust and identity, and how several objects answer. This page groups what changes for code and deployments built on v0.11.0.

:::note[This guide and the changelog]
The [0.12.0 section of the changelog](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/CHANGELOG.md) lists every change by area and issue, and its migration notes give the exact replacements. This guide groups what changes for code written against v0.11.0.
:::

## Before updating

Record your current package/binary version, enabled features, platform, transport, and important application workflows. Back up persisted Audit Log snapshots before the first start on v0.12.0. Keep a known-working deployment or environment available according to your operational policy.

## Update the selected interface

In a Python virtual environment:

```sh
python -m pip install --upgrade rusty-bacnet==0.12.0
```

For Rust, move every `bacnet-*` dependency to `0.12.0` together; all eleven crates share the version, and `bacnet-endpoint` and `bacnet-cli` are new on crates.io. For the CLI, [download the v0.12.0 executable](/rusty-bacnet/start/installation/#install-a-cli-executable), check it against `SHA256SUMS`, and confirm its version and features.

The packaging changed too:

- The Linux CLI executables need glibc 2.17 or newer and no libpcap package; v0.11.0's needed glibc 2.39 and libpcap. The Windows executable no longer needs the Visual C++ Redistributable.
- Wheels now cover CPython 3.14 as well as 3.11 to 3.13.

## Rust API

- `BACnetClient::builder()` and `BACnetServer::builder()` are gone; use `bip_builder()`. `ObjectIdentifier::new_unchecked` is gone too; use the validating `new` or `new_addressable` (#847, #873).
- `Error` gains `Structured`, which the client returns for a structured error body: some list-write refusals that came back as `Error::Protocol` now come back as `Error::Structured`, so match both for the class and code. `Error` also gains `UnsupportedTransport`, `Error::Decoding` carries a `DecodingKind`, and `Error::InvalidTag` is gone; match `kind: DecodingKind::InvalidTag` instead (#956, #1026, #1047, #1048, #1446).
- `subscribe_cov_property` takes a `CovPropertySubscription`, routed sends take a `RoutedTarget`, and `AnyTransport::Bip` holds its `BipTransport` in a `Box` (#902).
- More constructed-value codecs are free functions in `bacnet_encoding::constructed`: the calendar and schedule codecs (`bacnet_services::schedule` and `BACnetDateRange::encode`/`decode` are gone), the event notification codecs (`EventNotificationRequest` and `NotificationParameters` lose `encode`/`decode`), and `PropertyReference` and `ReadAccessSpecification`, now in `bacnet_types::constructed`. The ReadRange, WritePropertyMultiple and recipient encoders return `Result`, and `tags::decode_optional_context` is gone (#771, #793, #996, #1134, #1156, #1276, #1374).
- Alarm and event types use the `bacnet-types` enumerations and bit strings, such as `EventState` and `StatusFlags`, instead of raw integers (#914, #930, #932).
- Who-Is and Who-Has take one optional `DeviceInstanceRange` instead of two limits. `VTOpenRequest`, `WhoAmIRequest` and the WriteGroup request carry their standard fields (#912, #1483).
- `subscribe_cov_property` takes a `NonZeroU32` lifetime. Audit queries take a three-state `BACnetSuccessFilter` and a `u64` cursor, and ReadRange indices and sequence numbers are `u64` (#345, #802, #1092).
- `ServerConfig` and `ReceivedApdu` gain fields, such as the DCC, COV, mutation and request admission settings and the ingress network, global-broadcast flag and provenance, so struct literals need them (`ServerConfig` has `..Default::default()`) and patterns need `..` (#522, #1225).
- `CanonicalPeer::from_source` takes the local network number; `None` keeps the old matching (#1465).
- `decode_npdu` returns `NpduDecodeError` instead of `Error` (#1141).
- A custom `TransportPort` must provide `local_receive_apdu_capacity()`, `max_apdu_length()` is now `egress_apdu_limit()` with no alias, and `ReceivedNpdu` gains `provenance` and `direct_response` (#693).
- `PropertyPresenceCondition::IntrinsicReporting` splits into `IntrinsicReportingRequired` and `IntrinsicReportingOptional`; give a custom object's rows the one its table names (#1485).
- The PICS generator's `CharacterSet` renames or drops four variants to match the six standard character sets (#913).

## Python API

- A Rust panic raises PyO3's `PanicException`, which `except Exception` misses. A transport failure raises `BacnetTransportError`, which is also an `OSError` (#1002, #1120).
- An integer outside its field's range raises `OverflowError` everywhere, and an oversized object type raises `ValueError` (#847, #1360).
- An array or list reads as a `list` at any length. Local `read_property` and `write_property_local` behave like network requests and raise `BacnetProtocolError` (#1296, #1297).
- The properties in the Python API's [typed constructed values](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/docs/python-api.md#typed-constructed-values) table, such as Recipient_List, a Group's members and Present_Value, a Command's Action, the Access Rights rules and schedules, read as typed mappings, tuples and identifiers instead of `application_data` octets, so comparisons against octets change. Other constructed values still read as octets. Writing a read value back still works (#1310, #1344, #1345, #1487).
- Dates carry the full year, so drop any `+ 1900`; an unspecified year is 255, `rusty_bacnet.UNSPECIFIED`. `time_synchronization` and `utc_time_synchronization` need a specific date and time (#1501).
- `comm_state()` returns `EnableDisable` values, which are all truthy; compare with them or call `.to_raw()` (#1431).
- `successful_actions_only` takes 0, 1 or 2 (1 for the old `True`), and the alarm calls take enum values. Who-Is limits come in pairs (#345, #914, #1483).
- New required parameters: `vt_open` takes a `VTClass` and a local session identifier, `who_am_i` the vendor ID, model name and serial number, and `write_group` names each change by channel number (#912). `write_property_local` needs the keyword `source_object` (#824).
- `add_bip_network_port` replaces `add_network_port` (#867).

`ObjectIdentifier`, `PropertyValue` and `BACnetTimeStamp` can now be copied and pickled, and every exported class reports the `rusty_bacnet` module (#1500); nothing needs to change for that.

## Wire behavior

- The server ignores a confirmed request sent by broadcast or multicast, and the stack won't send one to a group address. Address each device by unicast or a routed DNET/DADR (#1257, #1479, #1493).
- An undecodable confirmed request draws a Reject naming the fault, and trailing octets or wrongly tagged members are refused (#1374, #1375, #1411, #1446).
- A Who-Is or Who-Has carrying only one range limit is dropped (#1447, #1483).
- AddListElement and RemoveListElement errors name the first failed element; duplicates are skipped and a missing element fails the whole removal. CreateObject and SubscribeCOVPropertyMultiple errors carry their full bodies (#1026, #1027, #1047, #1048).
- ReadRange reads only lists. SubscribeCOVPropertyMultiple stops at the first failing reference. SubscribeCOVProperty and SubscribeCOVPropertyMultiple refuse a zero lifetime; SubscribeCOV still treats zero as indefinite (#802, #1025, #1058, #1059, #1102).
- Priority_Array is read-only; command and relinquish through Present_Value with a priority (#842).
- Default_Color, Default_Color_Temperature and Color_Command use their standard property identifiers instead of 508 to 510, which belong to Network Port; use the named constants (#887).
- Who-Am-I, You-Are, VT and WriteGroup encode in the standard form (#912).
- Log records carry Log_Status with bit 0 first, so log-disabled no longer reads as log-interrupted (#1233).
- Addresses longer than 18 octets are refused by the address codecs, the recipient encoders and You-Are (#1098, #1156, #1200).
- While DCC disables initiation, the server skips I-Have and `broadcast_i_am()` returns an error; Who-Is still gets an I-Am (#1388).
- Notifications to a recipient on the local network number go out as local traffic (#1299).
- Lighting Output carries out its lighting commands: fades and ramps move Tracking_Value over time, steps and STOP act on the priority array, and the warn commands (also Present_Value -1.0 to -3.0) blink and hold for Egress_Time when Blink_Warn_Enable is TRUE. Lighting_Command_Default_Priority refuses 6 (#1384).

## CLI

- `bacnet --sc` requires `--sc-ca` with the site CA and no longer loads the system roots (#513). See [BACnet/SC](/rusty-bacnet/guides/bacnet-sc/).
- `bacnet read-range` decodes log records, and its JSON lists them under `records` instead of `items` (#1274).
- The Docker test tools in `benchmarks/` changed too: `bacnet-sc-hub` requires `--ca`, `--cert`, `--key` and `--device-uuid`, and `bacnet-device --transport=sc` needs SC credentials and a device UUID (#513, #517).

## Transports

- BACnet/SC needs mutual TLS 1.3 with explicit CA trust. `ScHub::start` takes an `ScHubTlsConfig` instead of a `TlsAcceptor`, and the node builders an `ScNodeTlsConfig` instead of a rustls `ClientConfig`, both built from DER. In Python, pass `sc_ca_cert`, `sc_client_cert` and `sc_client_key`, and `ca_cert` for `ScHub` (#513).
- Every SC hub and node needs a nonzero device UUID: `sc_device_uuid` for a Python client or server, `device_uuid` for `ScHub`. Provision it once and keep it for the device's life (#517).
- Read SC link state with `connection_state_changes()` instead of `ScTransport::connection()`, and MS/TP counts with `diagnostics()` instead of `node_state()`. An SC hub bind failure is `Error::Transport` (#956, #1104).
- B/IPv6 with `::` or no interface picks one usable non-loopback multicast interface and a unique address on it, keeps traffic on that link, and fails startup when the choice is ambiguous; pass a concrete address then. v0.11.0 asked the routing table for an address and fell back to `::1` when that failed.
- A B/IP BBMD bound to `0.0.0.0` fails `start()` when it can't tell its own address; bind the interface address instead (#937, #952).
- A device or router binding at a multicast or broadcast address fails `build()` and `start()`. B/IP drops forwarded packets from a group origin (#1493).
- `BACnetRouter::start` takes `RouterOptions` and returns a `StartedRouter` (#1220).
- Send a remote network's broadcast with `broadcast_to_network`, not `send_apdu_routed_via_local_broadcast` with an empty DADR. Routed confirmed requests refuse DNET 0, DNET 65535, an empty DADR and addresses over 18 octets (#1267, #1278, #1479).
- NPDUs and frames with addresses over 18 octets are dropped and counted, and router rejects go back to the original sender (#1141, #1158, #1198).
- `NetworkPortObject::new` gives way to `NetworkPortObject::new_bip` with a `BipPortConfig`, and Python's `add_network_port` to `add_bip_network_port`; a registered NORMAL B/IP Network Port follows its real bind (#863, #867).

## Objects and server

- Objects serve the properties their standard tables list. Undefined rows, such as Out_Of_Service on Command, answer UNKNOWN_PROPERTY, and missing required rows appear; regenerate your PICS (#979, #985, #1021, #1052, #1062, #1064, #1073, #1092, #1227, #1284, #1485).
- Constructed properties, from Lighting_Command and Color_Command to references and schedules, use their standard encodings and refuse the old octets. Rust reads them as `ApplicationData`; use the `bacnet_encoding::constructed` helpers. `BACnetLightingCommand` takes a `LightingOperation` (#980, #996, #1107, #1133, #1134, #1169, #1234, #1263, #1312, #1386, #1395, #1487).
- An indexed array read returns one element, or UNKNOWN_PROPERTY for an array the object lacks. An unset reference reads as instance 4194303, not NULL; write such a reference to clear it (#1034, #1296, #1417, #1426).
- Many setters validate and return `Result`, take typed values, or sit behind accessors such as `recipient_list()`. Device references refuse non-Device identifiers (#1029, #1087, #1088, #1098, #1149, #1182, #1249, #1285, #1308, #1316).
- Custom objects and wrappers adopt the reworked `BACnetObject` hooks for intrinsic reporting, life safety, COV increment, schedules and logs: `apply_life_safety_operation` returns a `LifeSafetyOperationOutcome` in place of the `_detailed` hook, and `impl_intrinsic_reporting!` is gone (#746, #752, #815, #845, #889, #1088, #1111, #1203, #1233, #1329, #1433, #1436).
- The server refuses DeviceCommunicationControl, even with the right password, until you pick a `DccPolicy` (`dcc_policy` in Python). `comm_state()` returns a `DccState` instead of a `u8`, and `handlers::handle_device_communication_control` is gone (#522, #1399, #1430).
- `CovAckResult::Error` carries the refusing answer as a `Refusal`, a `Data` variant is added, and the type is no longer `Copy` (#1323, #1342).
- Local writes take a `LocalCommandSource`. Writing a Command's Present_Value runs its Action list, and a Channel writes members in other devices (#824, #1150, #1264).
- A Notification Class Recipient_List holds at most 32 destinations, `add_destination` returns `Result`, and the flat list form from before #152 is gone (#1098, #1124, #1125).
- Log_Buffer reads only through ReadRange, and the pollers log any datatype. Trend Logs refuse COV logging for now (#1480), so stop a polled log by clearing Enable (#1092, #1233, #1236, #1354).
- Calendar follows the local date, and a Schedule evaluates in the standard order. A target that refuses its write sets the Schedule's Reliability to CONFIGURATION_ERROR (#1028, #1029, #1086, #1433).
- Access objects accept simulated writes while out of service and refuse NORMAL in their alarm values. A State_Text write sets Number_Of_States, and Averaging samples itself over a sliding window (#1083, #1131, #1144, #1149, #1247, #1401, #1443).

Request admission is new: the server caps the requests it works on at once, in total and per peer, and keeps a reserve for DCC recovery. [Request admission](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/docs/request-admission.md) gives its defaults and how to change them.

## Persistence

- Audit Log snapshots from v0.11.0 convert to the new schema on first load (#1233). Keep the backup until the converted log checks out.
- Custom Audit Log persistence runs on a plain thread with no Tokio context, and a panic fails the save (#1270).
- Durable saves finish on that writer thread, so a `BACnetServer` dropped without `stop()` returns before storage settles. Call `stop().await` before building another server on the same storage (#1270, #1409).
- A wildcard BBMD with a persisted BDT finds its own address from that table alone (#952).

## Verify more than import success

Exercise a known read, error handling, any routing or segmentation paths you depend on, subscription lifecycle, relevant server objects, and controlled cleanup. SC and MS/TP deployments need transport-specific validation, not only package-level tests.

Retest your application's output parsing where it depends on CLI JSON, typed Python values or Rust models: some constructed properties, dates and arrays read differently now. Separate regressions from corrected behavior that an older integration may have depended on accidentally. The [integration guides](/rusty-bacnet/development/overview/) explain shared endpoints, Network Port registration and SC setup, which are new or changed in this release.

## Sources and release scope

This guide covers the move from **v0.11.0** to **v0.12.0**. Source review is not hardware qualification.

[v0.12.0 release notes](https://github.com/jscott3201/rusty-bacnet/releases/tag/v0.12.0) · [Changelog](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/CHANGELOG.md) · [Rust API guide](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/docs/rust-api.md) · [Python API guide](https://github.com/jscott3201/rusty-bacnet/blob/v0.12.0/docs/python-api.md).
