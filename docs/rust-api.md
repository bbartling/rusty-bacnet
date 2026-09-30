# Rust API Reference

Rusty BACnet is a workspace of 8 published crates implementing the BACnet protocol stack (ASHRAE 135-2020).

This reference describes current development-source APIs, including unreleased
changes. Published crates and the site’s release tutorials target **0.11.0**; use the
[versioned Rust API](https://docs.rs/bacnet-client/0.11.0/bacnet_client/) and
[installation guidance](../README.md#installation) for that release. To use the
checkout APIs described here, follow [Build from source](../README.md#build-from-source).

## Crate Dependency Order

```
bacnet-types → bacnet-encoding → bacnet-services → bacnet-transport → bacnet-network
                                                                          ↓
                                                    bacnet-objects → bacnet-client
                                                                          ↓
                                                                   bacnet-server
```

---

## bacnet-types

Core BACnet types, enums, and error definitions.

### Enums (`bacnet_enum!` macro)

All BACnet enums are generated with `bacnet_enum!`, which produces a newtype struct with:
- `from_raw(value)` / `to_raw()` — convert to/from raw integer
- `ALL_NAMED: &[(&str, Self)]` — named constant list for iteration
- `Display` / `Debug` / `PartialEq` / `Eq` / `Hash` / `Copy` / `Clone`

```rust
use bacnet_types::enums::*;

let ot = ObjectType::ANALOG_INPUT;
assert_eq!(ot.to_raw(), 0);
assert_eq!(ObjectType::from_raw(0), ot);
```

**Key enums:** `ObjectType` (u32), `PropertyIdentifier` (u32), `ErrorClass` (u16), `ErrorCode` (u16), `EnableDisable` (u32), `ReinitializedState` (u32), `Segmentation` (u8), `EventState` (u32), `EventType` (u32), `NotifyType` (u32), `Polarity` (u32), `Reliability` (u32), `LifeSafetyOperation` (u32), `MessagePriority` (u32), `VTClass` (u32)

### Primitives

```rust
use bacnet_types::primitives::*;

// Object Identifier (type + instance, max 4194303)
let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1)?;
assert_eq!(oid.object_type(), ObjectType::ANALOG_INPUT);
assert_eq!(oid.instance_number(), 1);

// Property Value — tagged union
let val = PropertyValue::Real(72.5);
let val = PropertyValue::Boolean(true);
let val = PropertyValue::CharacterString("hello".into());
let val = PropertyValue::Null;
```

### Error

```rust
use bacnet_types::error::Error;

// Protocol error from a remote device
let e = Error::Protocol { class: 2, code: 31 }; // ErrorClass(2)=PROPERTY, ErrorCode(31)=UNKNOWN_PROPERTY

// Other variants: Timeout, Reject, Abort, RoutedPathTooLong,
// RoutedPathCapacityExceeded, Encoding, etc.
```

`Error::RoutedPathTooLong { dnet }` identifies the destination network from a
matching network-layer rejection; it does not claim an exact supported length.
`Error::RoutedPathCapacityExceeded { capacity }` reports that all bounded path
state is protected by a held/waiting gate or configured/learned evidence, so a
new path was rejected before transaction registration or frame emission.
`Error` is a public enum, so these variants can require new arms in downstream
exhaustive matches. Matchers with a wildcard arm are unaffected.

---

## bacnet-encoding

ASN.1/BER tag encoding, APDU/NPDU codecs, property value serialization, and segmentation.

### Property Value Encoding

```rust
use bacnet_encoding::primitives::{encode_property_value, decode_application_value};
use bacnet_types::primitives::PropertyValue;
use bytes::BytesMut;

// Encode
let mut buf = BytesMut::new();
encode_property_value(&mut buf, &PropertyValue::Real(72.5));
let bytes = buf.to_vec();

// Decode
let (value, bytes_consumed) = decode_application_value(&bytes, 0)?;
assert_eq!(value, PropertyValue::Real(72.5));
```

### Object identifiers

`ObjectIdentifier::new` validates the 10-bit object type (0..=1023) and 22-bit
instance (0..=4,194,303). `new_addressable` shares those checks and additionally
rejects the reserved wildcard instance 4,194,303. `ObjectType::from_raw` remains
an unrestricted selector; values above 1023 cannot form an object identifier.
Valid proprietary types and wire wildcard identifiers remain supported.

The safe `ObjectIdentifier::new_unchecked` constructor has been removed. Use
`new` or `new_addressable` and handle the error. The private fields and checked
construction keep encoding infallible without release-mode truncation; wire
decoding also establishes the field-width invariant.

### ValueSource CHOICE

`bacnet_types::constructed::BACnetValueSource` represents `None`,
`Object(BACnetDeviceObjectReference)`, or `Address(BACnetAddress)`.
The Object payload contains a required object identifier and an optional device
identifier; it replaces the earlier bare ObjectIdentifier payload.

`bacnet_encoding::constructed::encode_value_source(&mut BytesMut, &BACnetValueSource)`
returns `Result<(), Error>` and appends one framed CHOICE. Object-identifier widths
are validated at construction. Unencodable MAC lengths are rejected by this codec
before changing the buffer.
`decode_value_source(&[u8], offset)` returns `Result<(BACnetValueSource, usize), Error>`;
the second value is the next absolute offset, and suffix bytes remain available.
A consumer decoding a complete property payload must check that this offset equals
the payload length. Array or stream consumers can decode subsequent choices.

This generic datatype preserves wire-valid object types and wildcard instances,
network zero and empty broadcast MAC addresses. A source claim does not establish
an actual or authorized command origin. Existing BACnetTimeStamp codecs remain
the timestamp encoding authority.

### Command-source tracking

Analog Output, Binary Output and Multi-state Output, plus commandable instances
of the corresponding Value families, implement `Value_Source`, the 16-element `Value_Source_Array`, and `Last_Command_Time`.
These paired properties are required while this mechanism is enabled, including
in Property_List, REQUIRED RPM selection and PICS. Sources and the timestamp are
returned as `PropertyValue::ApplicationData` containing their BACnet CHOICE bytes;
source-array index 0 returns Unsigned 16. `Command_Time_Array` is not implemented.

A standalone command uses `BACnetObject::write_property_from` with an explicit
`bacnet_objects::command_source::CommandOrigin`. Remote origins contain the actual
BACnet address and an Unknown, Unique(Device), or Ambiguous correlation snapshot.
Local origins contain a concrete owning Device and an optional concrete initiating
object. Standalone calls validate syntax and trust the caller's declaration;
they do not authenticate it or check database membership. Context-free
`write_property` denies Present_Value commands and Value_Source corrections on
these six commandable families. Noncommandable Value modes use the direct write
contract described below and do not require command provenance.
`AnalogValueObject::set_present_value` was removed: configure
`set_relinquish_default` for a fallback or submit a sourced priority command.
Input measurement setters keep their separate contract. Priority_Array stays
read-only; a sourced Present_Value NULL relinquishes the specified priority.

The full server derives remote origins from direct network 0/source MAC or routed
SNET/SADR, independently of Audit reporting. Address-to-Device correlation is a
snapshot, not authentication. WP, WPM and CreateObject initial commands use that
origin. Schedule commands name the initiating Schedule and preserve complete
target references; Staging commands name the actual plan source after its existing
generation check. Failed CreateObject initialization rolls back the new object;
WPM retains its successful prefix and failed coordinate.

`BACnetServer::write_local` requires a final `LocalCommandSource` argument:
`ServerDevice` or `Object(oid)`. Both require a selected concrete local Device for
tracked commands; the object form also requires an existing concrete local
initiator under the database guard. Missing or wildcard-only Device identity and
missing initiators fail closed. Unrelated local writes retain their behavior
without a Device. The selected Device owns correction rights; changing the local
initiator changes the published source but not that owner. Custom objects retain
the default generic writer unless they implement the new hook. Writable
decorators must forward it, as the endpoint source-reporting decorator does.
The endpoint inbound write allowlist is unchanged.

Each priority retains its original command owner separately from its correctable
source claim. Remote correction requires the same uniquely known Device at both
operations, or the same actual address without conflicting known identities or
ambiguity. An originally unknown command cannot gain cross-address rights through
a later binding. Expiry permits retained-address fallback; ambiguity denies
correction. Router hop changes alone do not change the original routed address.
Local correction requires the same owning Device, independently of initiator;
remote and local owners cannot correct one another. An authorized owner may
assert any complete, valid ValueSource CHOICE, including none or a forwarded
object/address. Payload claims do not prove ownership. Correction preserves the
original token; a new command replaces it.

Last_Command_Time is an object-owned u16 SequenceNumber, initially 0, incremented
with wraparound only when a successful Present_Value command or relinquishment
changes the effective `(value, active priority, source)` tuple. Noncurrent-only
writes, source corrections and fallback configuration do not increment it.
A NULL command retains the relinquishing writer in that slot's source (the
selected interpretation of the last command), while the visible source moves to
the next active slot or none.

Single and Multiple subscriptions to commandable `Value_Source` on these six
families report `Present_Value`, `Status_Flags`, `Value_Source`,
`Last_Command_Time`, and `Current_Command_Priority` together. The trigger uses
the object's PV criterion (its `COV_Increment` for analogs), flags, source, or
priority changes; time alone does not trigger. A Value_Source subscription's
increment does not replace the analog object's increment. Initial and renewal
reports contain the same five fields. A failed or malformed required companion
suppresses that reference without advancing its delivered baseline; valid
Multiple siblings continue. Overlapping Multiple selectors share captured values
and deduplicate report fields, while only qualifying references advance their
own baselines and contribute timestamps. A qualifying explicit property selector
controls its field's timestamp, including an explicit false choice. For implicit
companions only, this implementation merges timestamp intent from qualifying
contributors; that overlap policy does not give unqualified selectors authority.
Existing delivery, lifetime and renewal
fences apply; same-generation concurrent completion ordering is separate (#826).

### APDU Types

```rust
use bacnet_encoding::apdu::*;

// Confirmed request, Complex ACK, Simple ACK, Error, Reject, Abort
// Segmentation: SegmentAck, segmented confirmed requests
```

### NPDU

```rust
use bacnet_encoding::npdu::{NpduHeader, encode_npdu, decode_npdu};

// Handles source/destination network addresses, hop count, priority
```

---

## bacnet-services

23 BACnet service modules with request/response encoding and decoding.

### ReadProperty / WriteProperty

```rust
use bacnet_services::rp::{ReadPropertyRequest, ReadPropertyACK};
use bacnet_services::wp::WritePropertyRequest;
```

`WritePropertyRequest::encode` returns `Result<(), Error>` and validates its
optional priority before modifying the destination buffer. Only omission or
1–16 is accepted, including NULL and noncommandable writes. Direct and routed
client WP paths propagate invalid input as a local `Error::Encoding` before
transaction admission or traffic; device-based calls validate before lookup.
This outbound contract does not change inbound semantic-error responses or
remote commandability rules.


### ReadPropertyMultiple / WritePropertyMultiple

`WritePropertyMultipleRequest::validate` checks the whole outbound request;
`encode` returns `Result` and leaves an existing buffer unchanged on validation
failure. Requests and each object's write list must be nonempty, targets cannot
be ALL/REQUIRED/OPTIONAL, and supplied priorities must be 1–16. Omitted priority,
index zero, proprietary properties, NULL and empty list values remain legal.
Direct and device-directed clients reject invalid requests before admission or
discovery. Inbound cursor/no-op and ordered-prefix error semantics are separate.

For a Device wildcard request `(Device,4194303)`, the bundled server's
ReadPropertyMultiple result wrapper names the resolved local Device, including
wrappers containing per-property errors. Its Object_Identifier value names the
same Device. Without a matching Device, the wrapper retains the wildcard and
its references return UNKNOWN_OBJECT. Concrete requests remain unchanged.

ReadPropertyMultiple response indexes follow the effective object declaration:
requested indexes remain on known arrays, including index zero and inline array
errors; scalar results omit them. Unknown objects/properties or unavailable
legacy declarations conservatively omit the response index. This does not alter
read error precedence or add a property read. Target Audit records retain the
requested index independently. See the
[scoped conformance evidence](conformance/support-summary.md).

```rust
use bacnet_services::rpm::{ReadAccessSpecification, ReadPropertyMultipleACK, ReadAccessResult};
use bacnet_services::wpm::WriteAccessSpecification;
use bacnet_services::common::{PropertyReference, BACnetPropertyValue};

let spec = ReadAccessSpecification {
    object_identifier: oid,
    list_of_property_references: vec![
        PropertyReference {
            property_identifier: PropertyIdentifier::PRESENT_VALUE,
            property_array_index: None,
        },
    ],
};
```

The low-level `WritePropertyMultipleCursorError.kind` distinguishes
`WritePropertyMultipleFailureKind::Syntax(RejectReason)` from
`PriorityOutOfRange`. This replaces the former `reject_reason` field. The
bundled server returns a formal WPM Error with `SERVICES / PARAMETER_OUT_OF_RANGE`
for a valid Unsigned priority outside 1..16, retaining the failed coordinate and
any successful prefix. Syntax failures retain initial Reject and post-prefix
`INVALID_TAG` behavior. Whole-request `WritePropertyMultipleRequest::decode`
returns `Error::Decoding` for either failure. Executed scope and evidence are
recorded in `BACNET-15-WPM-ORDERED-PREFIX-ERROR` in the conformance ledger.

### COV

```rust
use bacnet_services::cov::{
    SubscribeCOVRequest, COVNotificationRequest, UnsubscribeCOVRequest,
};
use bacnet_services::cov_multiple::{
    COVReference, COVSubscriptionSpecification, SubscribeCOVPropertyMultipleRequest,
};
```

### Discovery

```rust
use bacnet_services::who_is::{WhoIsRequest, IAmRequest};
use bacnet_services::who_has::{WhoHasRequest, WhoHasObject, IHaveRequest};
```

### Device Management

```rust
use bacnet_services::device_mgmt::{
    DeviceCommunicationControlRequest, ReinitializeDeviceRequest,
};
```

### Object Management

```rust
use bacnet_services::object_mgmt::{
    CreateObjectRequest, ObjectSpecifier, DeleteObjectRequest,
};
```

### File Services

```rust
use bacnet_services::file::{FileAccessMethod, FileWriteAccessMethod};
```

### ReadRange

```rust
use bacnet_services::read_range::{RangeSpec, ReadRangeAck};
```

### Alarm/Event

```rust
use bacnet_services::alarm_event::{
    AcknowledgeAlarmRequest, GetEventInformationRequest,
    GetAlarmSummaryRequest, GetEnrollmentSummaryRequest,
};
```

### List Manipulation

```rust
use bacnet_services::list_manipulation::ListElementRequest;
```

The shared AddListElement/RemoveListElement request exposes `validate()` and
transactional `encode(&mut BytesMut) -> Result<(), Error>`. A supplied array index
must be nonzero, and `list_of_elements` must contain at least one complete encoded
element. Validation checks tag framing with the shared parser limits (1 MiB per
primitive tag and 32 context levels including the service's outer `[3]`). It
honors application Boolean's no-payload encoding and preserves empty-valued,
constructed, context and vendor values. It does not validate every application
primitive or infer the remote property's datatype. Invalid requests leave the
output buffer unchanged; both client methods reject before transaction admission
or traffic. Inbound decoding and target property validation remain separate.


### Private Transfer

```rust
use bacnet_services::private_transfer::{
    ConfirmedPrivateTransferRequest, UnconfirmedPrivateTransferRequest,
};
```

### Text Message

```rust
use bacnet_services::text_message::{
    ConfirmedTextMessageRequest, UnconfirmedTextMessageRequest,
};
```

### Life Safety

```rust
use bacnet_services::life_safety::LifeSafetyOperationRequest;
```

### Write Group

```rust
use bacnet_services::write_group::{GroupChannelValue, WriteGroupRequest};
```

`WriteGroupRequest` follows the WriteGroup-Request production (Clause 21.3.2).
`group_number` is a `NonZeroU32` (group 0 is reserved) and `write_priority` is 1 to 16.
Each `GroupChannelValue` carries a `u16` channel number, an optional override priority
(1 to 16) and the already-encoded BACnetChannelValue in `value`: one
application-tagged primitive, or a context-0 lighting command, with no wrapper tag.
`encode` is fallible: it rejects priorities outside 1 to 16, an empty change list and
a value that is not a single BACnetChannelValue with `Error::Encoding`, leaving the
buffer unchanged. `decode` enforces the same rules and rejects trailing data.
Nothing in the bundled server executes inbound WriteGroup.

### Who-Am-I and You-Are

```rust
use bacnet_services::who_am_i::{WhoAmIRequest, YouAreRequest};
```

`WhoAmIRequest` has three mandatory application-tagged fields: `vendor_id` (`u16`),
`model_name` and `serial_number`. `YouAreRequest` has the same three plus optional
`device_identifier` (which must name a Device object) and `device_mac_address`; at
least one of those two must be present. Both `encode` methods are fallible and both
`decode` methods reject missing fields, context-tagged layouts and trailing data.

### Virtual Terminal

```rust
use bacnet_services::virtual_terminal::{
    VTCloseRequest, VTDataAck, VTDataRequest, VTOpenAck, VTOpenRequest,
};
```

### Audit

```rust
use bacnet_services::audit::{
    AuditLogQueryAck, AuditLogQueryRequest, AuditNotificationRequest,
    AuditPropertyReference, BACnetAuditLogQueryParameters, BACnetAuditNotification,
};
```

These models encode the corrected 2020 baseline: ANSI/ASHRAE 135-2020 plus
the Errata Summary 2024-04-29 (v1) items 7-8 for the Audit query contract.
In particular, `AuditLogQueryRequest::start_at_sequence_number` is the
corrected `Option<u64>` cursor at unchanged tag [2], and each query
alternative contains `successful_actions_only: BACnetSuccessFilter`
(`ALL`/`SUCCESSES_ONLY`/`FAILURES_ONLY`) at unchanged tags [7]/[4]. Unsigned
values use the library's `u64` implementation limit (1-8 octet canonical
forms). Storage filtering enforces all three states, and the continuation
cursor is literal (only identities below the cursor match, newest-first
insertion order even across `u64::MAX`-to-1 wrap). These codecs are not an
unqualified Clause 13.19 support claim; see the conformance ledger.

---

## bacnet-transport

Transport-layer implementations. All implement the `TransportPort` trait.

### Local receive capacity and outgoing limits

In the current development checkout, every `TransportPort` implementation must
provide `local_receive_apdu_capacity() -> u16`, a stable receive declaration.
Transparent wrappers and `AnyTransport` delegate it. The former transport method
`max_apdu_length()` is now `egress_apdu_limit()` without an alias: it describes
the current outgoing path, and SC negotiation/reconnect/failover can change it.
Client budgets continue using egress limits and the client's existing canonical
configuration policy. Unrelated Device, client and configuration APIs retain
their names.

`ServerConfig.max_apdu_length` is a raw receive ceiling. Startup clamps it to the
transport's local capacity, rejects an effective value below 50, and requires the
current selected Device's `Max_APDU_Length_Accepted` to equal that effective
value before starting the transport. The server does not rewrite an
application-owned Device. No Device remains a valid startup configuration but
cannot emit I-Am. Both live I-Am paths recheck the selected Device under the
same database guard; queued spontaneous announcements check at execution before
encoding or limiter accounting. A mismatched replacement refuses announcement,
and a later matching replacement restores it. Database replacement does not
rebind the discovery limiter's startup identity.

Raw declarations need not be header codes: Device/I-Am 1474 stays 1474, while
originated confirmed COV, Audit and Event notifications advertise the floor 1024
in their Confirmed-Request header. The codec helper
`max_apdu_header_at_or_below(u32)` returns the largest code in
50/128/206/480/1024/1476 not exceeding its input, rejects values below 50 and
saturates larger unsigned values at 1476. This conversion does not shrink raw
byte budgets or I-Am values. It is separate from the exact-code encoder API.

Built-in B/IP, B/IPv6, Ethernet and SC declare local APDU 1476; MS/TP declares 480.
Both registered B/IP port snapshots use local capacity independently of the
Device/server ceiling. SC nodes advertise and enforce local NPDU 1478, including
the two-byte plain NPDU header, on Hub, accepted-direct and outbound-direct
intake. Complete BVLC bounds, remote/path limits, routed overhead and the Hub's
forwarding capacity remain independent. These source APIs postdate published
0.11.0; this bounded evidence is not a full Annex AB or hardware qualification.

### Feature Flags

| Feature | Platforms | Transport |
|---------|-----------|-----------|
| (default) | all | BIP (UDP/IPv4) |
| `ipv6` | all | BIP6 (UDP/IPv6 multicast) |
| `sc-tls` | all | BACnet/SC (WebSocket + TLS) + SC Hub |
| `serial` | all | MS/TP (serial token-passing via `tokio-serial`) |
| `serial-gpio` | Linux | MS/TP + GPIO direction control (adds `gpiocdev`) |
| `ethernet` | Linux | BACnet Ethernet (AF_PACKET raw sockets with a best-effort BPF filter) |

### BIP (IPv4)

```rust
use bacnet_transport::bip::BipTransport;

let transport = BipTransport::new(
    Ipv4Addr::new(0, 0, 0, 0),  // bind interface
    0xBAC0,                       // port (47808)
    Ipv4Addr::BROADCAST,          // broadcast address
);
```

The socket binds the wildcard address so directed and limited broadcasts
arrive. Port zero asks for a private ephemeral port and never sets
`SO_REUSEADDR`: on Linux such a bind could otherwise be given a port another
`SO_REUSEADDR` socket already holds, and unicast to that port then reaches only
one of them. The choice is made at construction, so a restart that rebinds the
remembered actual port keeps it private. An explicit port still sets
`SO_REUSEADDR`, as before. On Linux that lets a second application bind the
same port, with the same single-receiver unicast caveat; macOS and BSD refuse a
second wildcard bind. B/IPv6 applies the same port-zero and explicit-port rule,
but binds a fresh ephemeral port on each start instead of remembering one.

### BIP6 (IPv6)

```rust
use bacnet_transport::bip6::Bip6Transport;

let transport = Bip6Transport::new(
    Ipv6Addr::UNSPECIFIED,  // select one unambiguous local link/address
    0xBAC0,                 // port
    None,                   // device_instance (auto VMAC)
);
// 3-byte VMAC, 3 multicast scopes, collision detection
```

Current source selects one concrete local address and OS interface for normal
B/IPv6 operation. `::` requires one usable non-loopback multicast interface (or
loopback if none exists), then a unique non-link-local address on that interface,
otherwise a unique link-local address. Multiple interfaces or addresses in the
selected class fail startup; configure an existing concrete address to resolve
ambiguity. A concrete address must have one usable local owner. This is local
selection policy, not an Annex U requirement, and differs from published 0.11.0's
wildcard address fallback.

The selected address and actual UDP port form `local_mac()`. One wildcard socket
receives selected unicast and BACnet multicast traffic; packet metadata fences
other interfaces and destinations before collision handling, VMAC learning or
NPDU admission. Every normal data/control send retains the selected source and
interface. Required joins and random-VMAC collision probing finish before
publishing startup state. Failed or cancelled startup, stop, restart and drop
reclaim the socket/task lifetime; port zero selects a fresh ephemeral port on
restart. Link-local addresses retain their OS zone internally but cannot reach
other links; `::1` is node-local. FF05/FF08 group scope alone does not prove
cross-link reachability.

With `register_as_foreign_device`, `::` instead derives a concrete unicast source
usable for the configured BBMD; an explicit source is retained. The production
socket is bound to that source, so registration, DBTN and ordinary unicast agree
with `local_mac()`. This branch requires the existing configured Device instance
and preserves trusted-BBMD handling without normal multicast prerequisites.

The selected-link wire fixtures qualify Linux on isolated ULA bridges and macOS
on loopback for multicast intake and unicast/control replies. Windows code is
compile-checked; its runtime remains unqualified. Unique link-local selection has
unit evidence, not physical-link wire qualification. This is bounded transport
evidence, not full Annex U conformance. External fixture commands and their
intentional exclusion from normal test runs are documented in
[the qualification guide](../crates/bacnet-transport/tests/ipv6_selected_link/README.md).

### BACnet/SC (Client Transport)

```rust
use bacnet_transport::sc::ScTransport;
use bacnet_transport::sc_tls::{ScNodeTlsConfig, TlsWebSocket};

let tls_config = ScNodeTlsConfig::from_der(ca_certs, node_cert_chain, node_key)?;
let ws = TlsWebSocket::connect("wss://hub:1234", tls_config).await?;
let transport = ScTransport::new(ws, vmac)
    .with_device_uuid(device_uuid) // caller's already-provisioned, durable [u8; 16]
    .with_heartbeat_interval_ms(30_000)
    .with_heartbeat_timeout_ms(60_000);
```

Production BACnet/SC transports validate heartbeat settings at `start()`: the interval must be
`3_000..=300_000` ms, and the disconnect timeout must be greater than the interval.

**Raw transport startup migration:** `new(ws, vmac)` remains two-argument and
infallible, with a zero UUID placeholder while unstarted. `with_device_uuid` is
required before `start()`: omitted/all-zero UUIDs and reserved all-zero/all-ff
local VMACs return clear `Error::Encoding` configuration errors. Error precedence
is reconnect configuration, heartbeat timing, then identity. No UUID version or
variant bits, EUI-48 shape, or Random-48 shape are enforced by this guard.

Identity failures precede transport-owned sends, receives, connector invocations,
socket consumption, channel/task allocation, and startup state changes. Sockets
are retained on repeated failure; correct a UUID with the existing consuming
`with_device_uuid` setter and retry on the **same owned WebSocket**. There is no
new VMAC repair setter. This cannot undo caller-owned WebSocket creation, dials,
or external work used to construct connector closures, nor does it promise
generic endpoint rollback or repairability of every configuration field.

The caller owns predeployment UUID generation and durable same-byte lifetime
reuse. Internal reconnect/failover/primary restore preserve the UUID, including
when a duplicate-VMAC NAK legitimately reselects the VMAC. This is **startup
enforcement, not lifetime immutability**: `connection()` still exposes mutable
`ScConnection` identity fields to applications. Pure `ScConnection` codec/manual
WebSocket use and later handshake validation are outside this guard.

`with_advertised_uris` configures known direct-connection URIs; it does not enable
accepting connections. Address-Resolution requests receive an ACK (with a
possibly empty URI list) only while a registered direct listener is live, its
VMAC/UUID matches, and both NPDU intakes remain open. Otherwise the node returns
COMMUNICATION/OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED (`7/45`). This current-live
availability policy is shared with Advertisement. Capability NAKs use the
existing rejection deadline and retirement behavior. See the
[scoped conformance evidence](conformance/standard-135-2020-ledger.md#node-address-resolution-accepting-capability).


### Direct peer membership and limits

`DirectListener::start(config)` creates a standalone direct listener.
`ScTransport::with_direct_listener(config)` registers its intake and shares one
UUID/VMAC owner with opt-in `with_direct_discovery` / `with_direct_tls`.
The returned listener handle may stop the listener independently; transport
stop/abort/drop also seals that registered listener and its response writers.
Retaining the handle permits explicit cleanup/join, not continued acceptance or
responses after transport teardown. A standalone listener retains its own lifetime.
Changing discovery does not erase accepted membership. Accepted and outbound
peers share identity uniqueness while retaining separate numeric quotas.

`DirectAcceptConfig::with_max_established_peers(M)` sets the established accepted
peer limit; its default is `DIRECT_ACCEPT_MAX_ESTABLISHED_PEERS` (16). Zero
normalizes to one. At most M handshakes may be pending and at most 2M accepted
physical sockets may exist, including retiring replacements. Values above
`usize::MAX / 2` fail before binding. `active_connections()` counts physical
sockets and can therefore reach 2M. Pending/physical saturation drops TCP;
otherwise a distinct valid Connect at accepted capacity receives the local
`RESOURCES/OTHER` NAK. Saturation does not guarantee reconnect admission.

**Pre-1.0 API break:** `with_max_connections` becomes
`with_max_established_peers`; the former physical-cap semantics and name are
removed, without aliases. The default constant now describes established
peers. Callers that use `active_connections()` must allow pending and retiring
sockets in addition to established peers.

A known UUID can replace its direct connection with the same or a free changed
VMAC. Successful Connect-Accept transmission precedes incumbent retirement;
failed or cancelled admission preserves the incumbent. A contender claiming a
third peer's VMAC receives `COMMUNICATION/NODE_DUPLICATE_VMAC`, preserving both
incumbents. This compound-conflict precedence and the capacity error pair are
local policy. Replacing an outbound peer still needs an accepted slot.
Outbound sends verify the peer's Connect VMAC against the requested destination.
The outbound pool retains at most 16 peers, with 16 pending dials and 32 physical
sockets per enabled discovery owner; expiry, eviction and disable retire only
their own generation. An idle worker observes remote EOF/Close and answers a valid Disconnect request
before closing. Malformed Disconnect requests use the existing control validator.
Disable/drop cancels owned outbound socket workers; asynchronous stop also joins them.

Simultaneous replacements can select opposite sockets at the two endpoints and
leave no live direct connection. Membership guarantees at most one current
connection per peer; normal Hub fallback and bounded URI backoff/retry apply.
A successful local WebSocket write does not confirm remote NPDU delivery.

Private process-wide generations fence new work from old sockets and stale
cleanup. Already queued complete NPDUs retain their original values, including
the [direct TLS identity snapshot](#accepted-direct-tls-identity). UUID claims
are not certificate bindings. The bounded
[server response policy](#accepted-direct-server-responses) is separate from
[ordinary bidirectional routing](#bidirectional-direct-traffic).

### Bidirectional direct traffic

Current native source selects an established matching accepted or outbound direct
connection before optional URI discovery, even when discovery is disabled.
Broadcasts continue through the Hub. Configure `with_direct_tls(ScNodeTlsConfig)`
before start for built-in TLS dial-out with application intake and matching
original-response authority. This works independently of the Hub adapter type.
A valid Connect and membership publication precede application use. Ordinary
direct frames omit both VMAC fields, retain Data Options, and obey the peer's
independent NPDU and complete BVLC limits. The existing bounded intake applies to
both direct roles; stale generations cannot admit new frames, while already
admitted immutable envelopes retain their original identity and reply capability.

**Pre-1.0 API break:** `with_direct_dialer` is replaced by
`with_custom_direct_dialer`, with no alias. Arbitrary factories remain application
send-only, including closures returning `TlsWebSocket`; they cannot attest a TLS
leaf or mint a direct identity/capability. Use the built-in `with_direct_tls` path
for authenticated bidirectional intake. Verified leaf capture also works on TLS
resumption using rustls's authenticated session identity; a resumed handshake need
not retransmit the certificate. This does not attest that a remote server requested
or verified the local certificate, or bind its certificate to its UUID/VMAC claims.

The current direct queue is shared by ordinary and original-response writes:
64 queued operations plus at most one active write. Saturation returns an error
without Hub fallback. Queue cancellation, owner shutdown and retirement are checked
before writing, and reads (including Ping/Pong) alternate with bounded writes.
Only definitely unstarted work on a retired route permits a fresh route decision;
an uncertain started write is never duplicated through the Hub or another dial.
The existing original-response capability always fails closed after retirement.
Disabling discovery retires outbound workers but keeps accepted membership; stop,
abort and drop seal the transport lifetime irreversibly.

Outgoing client and native confirmed-notification transactions retain BACnet's
canonical peer-address/Invoke-ID correlation, with existing service, direction
and segment-phase checks. Responses may switch Hub/direct paths. A replacement
peer claiming the same address can complete or control an old pending outgoing
transaction; this is not proof of same-leaf continuity. Optional historical-route
filtering is separate from the selected original-socket policy for incoming replies.
No outgoing transaction/retry policy changes here. This source behavior postdates
published 0.11.0 and adds no Python direct-entry API, Hub-relayed end-to-end identity,
full Annex AB or certification claim. See the
[scoped evidence](conformance/standard-135-2020-ledger.md#bidirectional-direct-traffic).

### Accepted direct TLS identity

Current source carries `TransportProvenance::direct_sc_identity()` through
accepted-direct and built-in outbound TLS ingress, the network queue, and server dispatch. It returns a
sealed, immutable `DirectScIdentity` with read-only `leaf_sha256()` and
`incarnation()` accessors. The fingerprint hashes the exact verified TLS leaf
DER; it does not hash PEM text, a public key, or claimed UUID/VMAC/SNET/SADR.
Same-leaf reconnects have different incarnations, and certificate rotation
changes the fingerprint. Incarnations are process-lifetime identifiers, not
persisted identity or an ordering API. Both values are `Copy + Eq + Hash`;
their `Debug` output omits fingerprint and incarnation.

Both built-in direct TLS roles capture the verified leaf before WebSocket upgrade and admit
NPDUs under the committed membership generation's fence. A missing verified
chain fails closed. Already admitted complete work may finish after close or
replacement under its original snapshot; it is not revoked or reinterpreted
using the new VMAC owner. Generic confirmed duplicate admission and the local
LSO replay store partition by this leaf/incarnation in addition to their existing
request keys. Generic duplicate detection now retains only pending operations;
LSO keeps its separate completed replay policy. Same-socket pending detection,
non-direct canonical keys, and capacity bounds remain unchanged. See
[confirmed transaction lifetimes](#confirmed-transaction-lifetimes).
Receive reassembly and client Abort cancellation also isolate direct incarnations.
Delayed, already-admitted A segments can finish A's context after replacement;
new frames from retired A cannot enter it.

Mutation and LifeSafetyOperation authorization contexts expose
`direct_sc_identity()`. Every WPM element retains the request's one snapshot,
with existing per-element ordering and authorized-prefix behavior. Application
policy still decides permission. `MutationTrust` and `ControlTrust` remain
scope labels; claimed addresses remain claims. **Pre-1.0 API change:**
`LifeSafetyOperationAuthorizationContext` now includes `provenance`, and its
`Debug` output redacts addresses and request inputs. Hub admission callbacks
report `is_hub_channel()` rather than `is_direct_peer()`; that scope-only value,
Hub-relayed ingress, and unverified transports return no direct identity.

These source APIs postdate published 0.11.0. This does not provide a Python
principal callback, certificate-to-claim binding, Hub-relayed end-to-end identity,
or a Python direct connection entry point. The narrower server response
capability below is separate from authentication provenance.

### Accepted direct server responses

Current native `BACnetServer` replies to verified direct confirmed requests only
through their original TLS connection, for accepted and built-in outbound peers. This covers SimpleACK, ComplexACK,
Error, Reject, server/overload Abort, LSO replay, segmented responses and retries,
and segmented-request SegmentACK/Abort. Replacement, closure or missing/mismatched
capability fails closed: there is no current-VMAC, replacement-socket, Hub or
new-dial fallback. Complete admitted work may still execute under its original
authorization; failure to reply does not roll it back or prove remote receipt.
Unconfirmed Who-Is/Who-Has discovery replies retain ordinary routing and are
outside this confinement guarantee.

**Pre-1.0 API change:** `ReceivedNpdu` and `ReceivedApdu` add
`direct_response: Option<DirectResponse>`; custom constructors use `None` for
unverified ingress and forwarding consumers preserve the original value.
`TransportProvenance` and `DirectScIdentity` remain `Copy + Eq + Hash`.
The separately sealed, cloneable `DirectResponse` exposes its read-only identity
and has redacted `Debug`; clones retain neither socket nor membership.
`ReceivedApdu::response_route()` saves a `ResponseRoute`. Server response helpers
use `NetworkLayer::send_response_apdu_on_issuance`, retaining routed DNET/DADR
encoding while selecting only the original direct writer. Verified direct
provenance without matching capability is an error; non-direct requests retain
ordinary routing and MS/TP reply handoff. Generic pending ownership still ends
at local encoded operation issuance, not the eventual send result.

Each direct connection has one socket writer and a shared 64-item ordinary/reply
queue, plus at most one active write. Ordinary saturation can reject a reply.
Queue saturation fails immediately; queue wait and each write are bounded by
the configured Connect timeout. The writer checks original membership and the
network/server's irreversible `DirectResponseScope` before starting queued work.
Network stop/drop and server stop/drop seal that scope synchronously. Low-level
capability callers must retain a scope for their owner and seal it at shutdown;
a sealed scope never reopens. Cancelled queued work is skipped. Already-started
writes cannot be recalled; timeout or a failed/retired write closes the worker.
The peer's negotiated Max-NPDU-Length and complete Max-BVLC-Length are checked.
`DirectResponse::max_npdu_length()` exposes that immutable payload budget;
`ResponseRoute::max_apdu_length(cap, destination)` subtracts the same encoded
local/routed NPDU header used for issuance. Following Clause 5.2.1.2, server
response selection uses the minimum of this path budget, the requester's APDU
acceptance and the server's configured APDU cap. ComplexACK segments fill this
budget subject to the existing segment-count and capability limits. If no
segment fits, the existing Abort path applies; if even that cannot fit, the
bounded send fails without fallback. Sizing never requires current membership
and does not revoke admitted execution; invalid authority still fails at send.
Response and received WebSocket frames alternate preference: a ready binary,
Ping or Pong frame can precede a queued response by at most one read turn, and
a full response queue can precede input by at most one bounded write. Ignored
controls yield a scheduling turn without extending the binary-activity idle
deadline; handshake control filtering retains the absolute Connect timeout.

Segmented-response ACK/Abort admission includes the original direct leaf and
incarnation. A reconnect cannot advance or cancel an old response child.
Receive reassembly saves segment zero's response capability separately from
its authorization snapshot; final completion uses that saved route.

This is selected local confinement policy, not a Standard requirement to deliver
on a historical socket. It postdates published 0.11.0 and qualifies only the
native server consumer described here. The [client and endpoint supplement](#accepted-direct-client-and-endpoint-replies)
qualifies those additional inbound reply consumers. Outgoing client transaction
correlation retains the [standard path-switching behavior](#bidirectional-direct-traffic). No full
Annex AB, external interoperability or certification claim follows. See the
[scoped response evidence](conformance/standard-135-2020-ledger.md#accepted-direct-server-responses).

### Accepted-direct client and endpoint replies

Current source extends the selected original-socket response policy to standalone
`BACnetClient` handling inbound confirmed COV/Event notifications and unsupported
or segmented confirmed requests, and to `EndpointSession`'s existing narrow
ReadProperty/authorized Device WriteProperty responder. This postdates published
0.11.0. It does not change outgoing client transactions, their retries or their
terminal/segment-control admission. Ordinary direct routing now applies as
described [above](#bidirectional-direct-traffic). BACnet permits response path switching; this is a
local confinement policy for these incoming-request consumers, not a universal
protocol correlation requirement.

Direct provenance **or any supplied direct capability** selects checked response
issuance before `reply_tx`. Missing, mismatched, retired or sealed authority fails
without a prompt-channel, address, replacement, Hub or new-dial fallback. Ordinary
non-direct/no-capability ingress keeps existing MS/TP behavior: the standalone
client falls back to ordinary routing after a failed prompt handoff, while the
endpoint completes that prompt attempt even if its receiver closed. Endpoint
reply suspension only consumes ordinary prompt work. Group requests and the
client's COV `NoResponse` policy remain silent.

The endpoint carries the saved `ResponseRoute` through its existing bounded
egress queue (`SessionConfig.queue_capacity`). The hidden composition method
`EndpointEgress::admit_response_apdu` returns caller-owned completion: dropping
it retracts queued work. Stop/drop closes admission and cancels queued work;
retained role handles cannot extend that lifetime. The direct socket still has
the shared 64-item ordinary/reply writer queue and its existing bounded I/O. An already-started
write cannot be recalled, and local completion does not prove peer receipt.

After service execution, the endpoint caps a ComplexACK by the requester APDU
limit and saved peer NPDU/BVLC limits using the actual local/routed NPDU header
(Clause 5.2.1.2). It has no segmented response sender: an oversized ACK selects
its existing `SEGMENTATION_NOT_SUPPORTED` Abort. If that Abort cannot fit, checked
send fails without fallback. Retirement or invalid reply authority does not
revoke the original authorization or roll back an admitted Device write.
Direct responses use empty outgoing Data Options; ordinary endpoint egress keeps
its existing data-attribute and destination behavior.

[Scoped real-TLS and lifecycle evidence](conformance/standard-135-2020-ledger.md#accepted-direct-client-and-endpoint-replies)
uses public client/session paths, held A envelopes and distinct-leaf B replacements,
mixed prompt channels, exact response budgets and cancellation barriers. It is
neither a full Annex AB claim nor Python direct-listener/API support.

### Hub certificate bindings

`ScHubCertificateBinding::new(uuid, allowed_vmacs, leaf_sha256)` creates one
immutable installation group. The UUID is a nonzero 16-byte value; VMACs are
distinct nonreserved six-byte values, and fingerprints are distinct 32-byte
SHA-256 digests of the **exact leaf certificate DER**. Both lists must be nonempty.
`ScHubCertificateBindings::new(Vec<ScHubCertificateBinding>)` rejects empty maps
and any UUID, VMAC or digest shared by groups. Multiple digests in one group
authorize explicit certificate rotation; multiple VMACs authorize only those ports.
All inputs are owned. Debug and errors omit certificate and policy contents.

Install the map with `ScHubTlsConfig::with_certificate_bindings(bindings)`.
An absent map retains CA-valid admission. A configured map admits only listed
verified leaves with the group's exact UUID and one allowed VMAC; even unreserved
claims from an unmapped leaf are denied. UUID/VMAC reservations exist while the
node is offline. Local Hub VMAC overlap fails before binding; there is no extra
restriction on a group's UUID matching the hosting device UUID.

The Hub hashes the verified leaf after TLS acceptance. Under the registry lock,
it checks the map before the existing admin callback, deadline commit, insertion
or incumbent replacement. Callback Allow cannot override a binding denial; Deny
or panic still refuses a matching leaf. Existing collision, capacity, deadline
and same-UUID replacement rules then apply, including to listed renewals.
Denied attempts leave incumbent membership/relay intact and increment the existing
redacted `admin_denied` counter. Cloned configurations share immutable policy,
with independent live registries and counters.

This is opt-in installation policy allowed by 135-2020 Annex AB.7.4, not its
default authentication requirement. Configure every Hub feeding a trusted router
ingress consistently. It does not convey a certificate principal in relayed BVLC
frames, authorize BACnet operations, bind direct-peer requests, or complete the
Annex AB security profile (#518/#524 remain separate; accepted-direct identity
is described [above](#accepted-direct-tls-identity)). Runtime tests use
distinct real same-CA leaves, native registration/relay and joined shutdown;
[the ledger](conformance/standard-135-2020-ledger.md#hub-certificate-bindings)
records the bounded evidence.

### BACnet/SC Hub

```rust
use bacnet_transport::sc_hub::{ScHub, ScHubHandshakeTimeouts, ScHubTlsConfig};

// Owned, already loaded DER: Vec<CertificateDer<'static>> for both lists,
// and PrivateKeyDer<'static> for hub_key. File loading belongs to the caller.
let tls = ScHubTlsConfig::from_der(ca_certs, hub_cert_chain, hub_key)?;
let mut hub = ScHub::start_with_tls_config(
    listen_addr, tls, hub_vmac, hub_uuid, ScHubHandshakeTimeouts::default(),
).await?;
let addr = hub.local_addr().expect("started hub has a bound address");
// ... use the hub ...
hub.stop().await;
```

The SC hub is a TLS WebSocket relay. Both clients and servers connect to it as spoke nodes. Messages are routed by VMAC address.

`ScHubTlsConfig::with_admission_policy` receives `ScHubAdmissionInput::registration`
as one fixed `ScHubRegistrationKind`: `Initial`, `SameUuidSameVmac`,
`SameUuidMovedVmac`, or `ConflictingVmac`. Classification and policy run under the
same registry lock before registration commit; Allow still applies ordinary
collision and capacity rules. The labels reveal no incumbent identity fields.
A known UUID moving onto another UUID's VMAC is classified as `ConflictingVmac`.
UUID equality is a payload claim, not certificate-principal authentication.
The default accepts/replaces a known UUID as Annex AB requires; an operator may
explicitly deny the two same-UUID kinds as local security policy before protocol
acceptance. Denial leaves the incumbent untouched and retains the existing
RESOURCES/OTHER NAK and admin-denial counter. Policies remain synchronous,
nonblocking and panic-deny; they must not perform I/O or reenter the registry.


Every admitted transit relay attempt has one configurable local budget (five
seconds by default), including destination sink acquisition and WebSocket send.
It applies to NPDU/opaque unicast, each concurrent broadcast recipient, and
forwarded BVLC-Result. A timeout
lets that source process its next frame; it does not retry, fabricate a Result,
or retire the destination solely for timing out. Terminal send errors retain the
existing captured-connection retirement rules, and heartbeat liveness is separate.
Cancellation cannot retract bytes already buffered by the WebSocket. Broadcast
fanout remains concurrent; a healthy recipient need not wait for a blocked one.
Probe, control, cleanup and graceful-shutdown policies remain separate; shutdown
may force cleanup before a blocked relay's send deadline.

Peer-initiated WebSocket Close is answered through the connection lease, including
upgraded peers that have not sent Connect and peers closing while the Hub awaits
Disconnect-Ack. Cleanup flushes the queued reciprocal frame within the local
five-second sink acquisition/I/O bound after retiring the matching registration.
Close without Disconnect-Ack still yields a forced graceful-shutdown outcome;
forceful abort may forgo the reply. The [scoped conformance evidence](conformance/standard-135-2020-ledger.md#hub-reciprocal-websocket-close)
covers WebSocket replies, not TLS `close_notify` behavior.

`ScHubTlsConfig::with_relay_send_budget(Duration)` validates this separate
transit budget; `validate_relay_send_budget` supports preflight before
loading TLS files. This replaces the pre-1.0 unicast-only setting without an
alias; update callers to `with_relay_send_budget`, `relay_send_budget` and
`validate_relay_send_budget`. `ScHubProbePolicy::new(scan_interval, idle_age, ack_age,
send_budget)` configures the optional accepting-Hub probe through
`with_probe_policy`. Defaults are 30s/60s/5s/5s. Both policies require positive
whole milliseconds, at most `i64::MAX` milliseconds to reserve tick headroom,
and a future instant representable by the platform monotonic clock.

Each Hub owns one monotonic origin. A scan probes only after idle age strictly
exceeds its threshold; pending ACK age starts at reservation, before sink
acquisition, and retirement requires a later scan to observe strictly exceeded
ACK age. Serial send work or scheduling delays can postpone that scan; ACK age
is not a hard closure deadline. Missed ticks are skipped. Only a matching valid
ACK clears pending and refreshes activity. Wrong-ID or malformed ACKs do not.
The probe send budget includes acquisition and send. These are local Hub
policies, separate from the initiating node's normative 3–300s heartbeat range.

`ScHubBroadcastRatePolicy::new(sender_burst, sender_per_second, global_burst,
global_per_second)` checks the existing continuously refilled broadcast policy
before I/O. `with_broadcast_rate_policy` applies it unchanged; rates and bursts
must be in `1..=u64::MAX / 1_000_000_000`. Existing sender/global exhaustion
counters and silent-drop semantics remain. See [Hub operator policy evidence](conformance/standard-135-2020-ledger.md#hub-operator-timing-and-broadcast-policy).

`ScHub::status().await.outcomes` is a fixed `ScHubOutcomeCounts` snapshot:
committed UUID replacements, selected VMAC/capacity refusals, ordered accept
limit drops, TLS/WebSocket/Connect timeouts, eligible NPDU/opaque unicast
missing-target/length-limit/send-timeout/send-error outcomes, and actual
matching-generation heartbeat retirements. Each `u64` saturates, starts at zero
for each Hub, and never controls policy. Refusals count decisions, not delivered
NAKs; a later Connect timeout can also count. Snapshots are not transactional.
Malformed, pre-registration, stale-source, self/local, broadcast, and forwarded
Result paths are excluded from unicast counters. Retirement skips do not imply
send success. Existing admin/broadcast counters retain their meanings.
Rust status remains available after stop; a new Hub using the same address and
config owns fresh counters. See [Hub outcome evidence](conformance/standard-135-2020-ledger.md#hub-outcome-status).

With `sc-tls`, every public hub startup requires `ScHubTlsConfig`:
explicit nonempty CA trust anchors, mandatory WebPKI client verification, and
TLS 1.3-only local policy. Its fallible `from_der` constructor performs no file or
network I/O. Empty CA/chain, malformed DER (including a bad entry in an otherwise
valid list), unusable keys, and certificate/key mismatch return `Error::Encoding`
before startup can bind. The hub chain is leaf first. Configuration is private;
clones share the same policy, with no mutable/raw accessor or unchecked conversion.
The constructor uses the built-in aws-lc provider, not a caller-installed provider.

**Rust source-breaking migration:** the second parameter of `start`,
`start_with_uuid`, and `start_with_uuid_and_timeouts` is now `ScHubTlsConfig`, not
`TlsAcceptor`. Construct it with `from_der`; raw hub injection, including custom
verifiers/providers, TLS-version selection and arbitrary configuration knobs, is
retired with no public unchecked escape.

**Hub identity source/runtime break:** `ScHub::start(bind, tls, vmac, uuid)` now
requires the fourth UUID argument. All four public starts reject an all-zero
16-byte UUID or reserved UNKNOWN (all-zero)/BROADCAST (all-ff) local VMAC with
`Error::Encoding` before `TcpListener::bind`, through one shared enforcement point.
The other three method names, argument order and return contracts are unchanged.
No UUID version/variant or general VMAC bit-shape policy is added. Provision the
hosting device UUID before deployment and durably reuse it for its lifetime
(AB.1.5.3). Connect-Accept carries that device UUID and the hosting port's VMAC
unchanged (AB.2.11, AB.6), not an identity generated per connection. Persistence,
generation and detecting changed stored values belong outside this identity
argument. Peer registration bindings are configured separately on `ScHubTlsConfig`. Default or explicitly validated handshake budgets and lifecycle
are preserved. `start_with_tls_config` remains a compatible full-control alias for
`start_with_uuid_and_timeouts`. Built-in node APIs separately require
`ScNodeTlsConfig`, as described below; generic custom transports remain available.
Python hub startup uses the typed path internally. The standalone benchmark
hub/device and Docker SC pair now require explicit mTLS PEM files; see
[Secure Docker migration](../examples/docker/README.md).

Local configuration checks do not certify certificate dates or issuer
relationships: peers verify certificates at handshake time using rustls trust
anchors. Base Standard 135-2020 AB.7.4/AB.7.4.1.1 provides the mutual operational
authentication and installation-credential context; TLS 1.3-*only* is local policy,
not the Standard's TLS 1.3-*support* requirement. This does not add direct-issuer,
revocation or SAN policy, or close the full security
profile gap (#513 remains open for final acceptance assessment and the remaining
policy limits, not for a public raw hub startup path).

Evidence includes executable/compile-fail rustdoc, native preflight rejection,
TLS 1.3 mutual authentication with Connect-Accept and relay barriers after missing,
wrong-issuer, expired, not-yet-valid client and TLS 1.2 denials, custom phase
deadlines, and explicit stop. All three formerly raw startup methods have live
positive/negative coverage and wrong-argument-type compile-fail examples; the old
TLS 1.2/server-auth-only characterization is intentionally retired. Installed Python tests separately exercise OpenSSL
peers and ReadProperty; these are not hardware or full-profile certification.

The already-mTLS benchmark hub launcher and the CLI ReadProperty and server SC-DCC
test fixtures also use the validated hub path with explicit test UUIDs, retaining timeouts,
authentication modes and cleanup. The benchmark PEM loader has focused empty,
malformed, mixed-valid/invalid DER and mismatched-key tests. Independent raw TLS
peer helpers (including TLS-version negative controls) retain their existing
signatures for independent peers, not public hub startup. The separate
standalone/Docker migration did not change production CLI or node APIs; the
subsequent built-in node API migration follows.
Benchmark compilation and functional TLS tests are not new performance qualification.
The server-auth-only `sc_latency`/`sc_throughput` targets are retired; the original
mTLS targets remain, with historical results and limits in [Benchmarks](../Benchmarks.md).

#### Strict local node TLS configuration

**Rust source-breaking migration:** `TlsWebSocket::connect(url, config)`,
`ScClientBuilder::tls_config(config)`, and `ScServerBuilder::tls_config(config)`
now require `bacnet_transport::sc_tls::ScNodeTlsConfig`, not
`Arc<rustls::ClientConfig>`. Names, argument order, return types, identity defaults,
and lifecycle behavior are unchanged. Load owned DER at your application boundary:

```rust
use bacnet_transport::sc_tls::{ScNodeTlsConfig, TlsWebSocket};
let tls = ScNodeTlsConfig::from_der(ca_certs, node_cert_chain, node_private_key)?;
let ws = TlsWebSocket::connect(hub_url, tls.clone()).await?;
// Or pass tls to BACnetClient::sc_builder().tls_config(tls), or
// BACnetServer::sc_builder().tls_config(tls), then finish that builder.
```

The factory accepts nonempty explicit CA and leaf-first operational chains plus a
matching usable key. It checks every DER entry before any I/O, uses the fixed
built-in aws-lc provider, normal WebPKI server CA/name verification, and TLS 1.3
only. It does not preflight local certificate dates, issuer relationships, EKU,
or authorization. No raw constructor, getter, mutable access, or unchecked
conversion exposes the underlying configuration. Clones share one configuration,
including its verifier, identity resolver and normal resumption cache; reconnects
do not rebuild it or disable tickets. Early-data policy is unchanged.

**Local contract limit:** the node offers credentials when requested and compatible.
A trusted TLS 1.3 server that sends no CertificateRequest can complete; resumed
connections may not retransmit certificates. This does not attest that every
connection presents an identity or that an arbitrary remote hub verifies it.
The independent server-side no-request and Full→Resumed tests characterize this
limit; strict hub and reconnect/failover tests cover the configured mTLS paths.
`WebSocketPort`, `ScTransport`, and generic builders remain public and generic;
other WebSocket implementations are outside this built-in driver guarantee.
Python constructors, CLI flags, file-I/O/error phases, and Docker provisioning stay
compatible; their existing node policy is consolidated internally. The local raw
configuration gap is closed, not the full Annex AB profile or issue #513.

### MS/TP (Serial RS-485)

MS/TP is a token-passing protocol over RS-485 serial, commonly used for field-level BACnet devices. The serial I/O is abstracted behind the `SerialPort` trait, with three RS-485 direction control modes.

#### Host Diagnostics and Qualification

Call `MstpTransport::diagnostics()` before moving the transport into its owner.
The cloneable `mstp::MstpDiagnostics` handle returns owned
`MstpDiagnosticsSnapshot` counts during operation and after stop/drop, without
retaining serial ownership. Counts start at zero, saturate at `u64::MAX`, and have
no reset. Relaxed loads are individually atomic, not a globally coherent snapshot.
These are redacted host events, not wire timestamps or proof of peer delivery.
See the [qualification method](mstp-qualification.md) and
[unrun result template](mstp-qualification-result.json) for before/after deltas,
the #707 rerun matrix, independent capture requirements and explicit non-claims.
No hardware qualification, timer change, Python/generic status API, or expanded
MS/TP routing/conformance claim is included.

#### Optional Dedicated Execution

Execution placement is configured separately from `MstpConfig`, preserving
existing master-node configuration literals and `SerialPort` implementations:

```rust
use bacnet_transport::mstp::{MstpConfig, MstpExecutionMode, MstpTransport};

let transport = MstpTransport::new(serial, MstpConfig {
    this_station: 1,
    baud_rate: 76800,
    ..MstpConfig::default()
})
.with_execution_mode(MstpExecutionMode::DedicatedThread);
```

Call the builder before `start()`. Omitting it (or selecting `Tokio`) keeps the
existing Tokio-spawn path; changing the builder setting does not migrate an
already-running loop. Dedicated mode runs the same MAC loop on an OS thread with
its own current-thread runtime. Read/write polling and blocking backend work are
isolated from application workers; native drain offloads use the isolated
runtime's blocking pool. This applies equally to UART and USB serial backends,
without changing frame order, drain boundaries, turnaround deadlines or the
64-entry NPDU receive channel. Async serial resources opened on another reactor
still require that original reactor to remain running.

`start()` reports thread/runtime creation failures without falling back to the
application pool. `stop()` waits for task and isolated-runtime teardown, clears
the transmit queue and sets the node to Idle. `abort()` and drop request
cancellation and release transport-owned state without waiting. Blocking calls
must return before their resources can be released; cancellation is not a drain
or rollback of driver-accepted bytes. As before, stopping does not make a
consumed serial transport restartable: construct a new transport to restart.

Isolation is an execution option, not a real-time guarantee or measured timing
claim: fast/efficient does not mean deterministic. RT policy/priority
(`SCHED_FIFO`), CPU affinity/pinning and reporting RT setup success/failure are
**deferred, not implemented**. PREEMPT_RT, IRQ, mlock and buffer-tuning deployment
guidance beyond this note, plus on-wire hardware qualification (#502), remain
out of scope. This is only the thread-isolation subset of #501; that issue remains
open for the residual RT work and full documentation.

#### Auto-Direction (USB RS-485 Adapters)

Most USB RS-485 adapters (FTDI, CH340, CP2102) handle direction switching in hardware — no configuration needed.

```rust
use bacnet_transport::mstp_serial::{TokioSerialPort, SerialConfig};

let serial = TokioSerialPort::open(&SerialConfig {
    port_name: "/dev/ttyUSB0".into(),   // Linux
    // port_name: "/dev/cu.usbserial-xxx".into(),  // macOS
    baud_rate: 76800,
})?;

// Use with BACnetClient or BACnetServer via generic_builder
let client = BACnetClient::generic_builder()
    .transport(MstpTransport::new(serial, 1, 127))  // station 1, max_master 127
    .build()
    .await?;
```

#### Kernel RS-485 Mode (Linux, RTS-based)

When DE/RE is wired to the UART's RTS pin, the Linux kernel can toggle it automatically via the `TIOCSRS485` ioctl. Zero userspace overhead.

```rust
let serial = TokioSerialPort::open(&config)?;
serial.enable_kernel_rs485(
    false,  // invert_rts: false = RTS HIGH during TX
    0,      // delay_before_send_us
    0,      // delay_after_send_us
)?;
```

Both delay arguments remain in microseconds but must be exact multiples of 1000:
zero is valid, and `1000` requests one millisecond. The Linux ABI stores whole
milliseconds, so fractional-millisecond requests return an error before any ioctl
instead of being rounded.

After applying the configuration, the method reads it back with `TIOCGRS485` and
checks that RS-485 is enabled with the requested RTS polarity and delays. Drivers
may reject or sanitize unsupported settings; set/readback failures and mismatches
return an error. A mismatch reports the effective flags and millisecond delays.
A readback or verification error can occur after the hardware configuration has
changed; the method does not roll back or retry. Success logs the verified effective
settings. See the [Linux RS-485 userspace ABI](https://cdn.kernel.org/doc/html/latest/driver-api/serial/serial-rs485.html).

#### GPIO Direction Control (RS-485 Hats)

For RS-485 hats where DE/RE is wired to a GPIO pin (e.g., Seeed Studio RS-485 Shield on Raspberry Pi with GPIO18), use `GpioDirectionPort` to wrap a `SerialPort` that implements transmit-complete `drain()`. Requires the `serial-gpio` feature.

```rust
use bacnet_transport::mstp_serial::{GpioDirectionPort, TokioSerialPort, SerialConfig};

let serial = TokioSerialPort::open(&SerialConfig {
    port_name: "/dev/ttyS0".into(),
    baud_rate: 76800,
})?;

// Wrap with GPIO direction control: gpiochip0, line 18, active-high
let port = GpioDirectionPort::new(serial, "/dev/gpiochip0", 18, true)?;

// Or with an additional guard interval after drain (microseconds):
let port = GpioDirectionPort::with_post_tx_delay(
    serial, "/dev/gpiochip0", 18, true, 200,
)?;
```

The `GpioDirectionPort` wrapper:
- Sets GPIO to receive mode (DE deasserted) on creation
- Switches to TX mode before each `write()`
- Waits for transmit-complete drain, including after a partial write error
- Starts the optional transceiver guard interval only after drain succeeds; the delay is not a substitute for drain and must fit the link's driver-release timing budget
- Switches back to RX only after completion and the guard interval
- Serializes I/O with direction changes; after a failed drain or cancelled write, the next read/write must finish draining before restoring RX
- Uses the Linux GPIO character device (`/dev/gpiochipN`) via `gpiocdev` — not deprecated sysfs

A drain error leaves transmit completion unknown and DE asserted. If recovery is
not possible, the caller must handle the failed port; dropping the wrapper is not
an asynchronous drain. Unix `TokioSerialPort` uses the native serial backend's
`tcdrain`-backed synchronous flush on a blocking worker, keeping the stream alive
and exclusive until the syscall returns. This does not qualify adapter or driver
on-wire timing. Auto-direction and kernel RS-485 writes remain unchanged.

#### SerialPort Trait

The MS/TP state machine is hardware-agnostic. Custom serial implementations (e.g., for testing) can implement:

```rust
pub trait SerialPort: Send + Sync + 'static {
    fn write(&self, data: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
    fn drain(&self) -> impl Future<Output = Result<(), Error>> + Send;
    fn read(&self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Error>> + Send;
}
```

`write()` may report driver acceptance before transmission finishes. `drain()`
reports completion of all accepted output, including the UART shift register.
Its default implementation returns an unsupported-operation error, preserving
existing custom backends without falsely claiming completion. Custom backends
used for software direction control must implement this operation. The loopback
backend completes writes in memory and drains immediately.

### Loopback Transport

```rust
use bacnet_transport::loopback::LoopbackTransport;

let (side_a, side_b) = LoopbackTransport::pair(
    vec![0x00, 0x01],  // MAC for side A
    vec![0x00, 0x02],  // MAC for side B
);
```

In-process channel-based transport for composing a client and server without real network sockets (e.g. inside an HTTP gateway). `LoopbackTransport::pair()` creates two connected transports backed by `tokio::sync::mpsc` channels — sending on one delivers to the other. Available as `AnyTransport::Loopback` for use with the enum dispatch wrapper.

### AnyTransport (enum dispatch)

```rust
use bacnet_transport::any::AnyTransport;
use bacnet_transport::mstp::NoSerial; // placeholder when serial feature is off

let transport: AnyTransport<NoSerial> = AnyTransport::Bip(Box::new(bip_transport));
```

Variants: `Bip` (boxed), `Bip6`, `Mstp`, `Sc` (boxed), `Loopback`.

### BBMD

```rust
use std::net::Ipv4Addr;
use std::path::PathBuf;

use bacnet_transport::bbmd::BdtEntry;
use bacnet_transport::bip::{BipTransport, DEFAULT_BACNET_PORT};

let mut transport = BipTransport::new(
    Ipv4Addr::UNSPECIFIED,
    DEFAULT_BACNET_PORT,
    Ipv4Addr::BROADCAST,
);

transport.enable_bbmd(vec![BdtEntry {
    ip: [192, 168, 1, 10],
    port: DEFAULT_BACNET_PORT,
    broadcast_mask: [255, 255, 255, 255],
}]);

// Optional: persist successful legacy Write-BDT updates and reload them on restart.
transport.set_bdt_persist_path(PathBuf::from("/var/lib/rusty-bacnet/bdt.bin"));

// Optional: restrict Write-BDT and Delete-FDT management operations.
// An empty ACL allows all sources.
transport.set_bbmd_management_acl(vec![[192, 168, 1, 100]]);
```

---

## bacnet-network

Network layer routing, router tables, and the multi-port router.

```rust
use bacnet_network::network_layer::NetworkLayer;
use bacnet_network::router::BACnetRouter;
```

---

## bacnet-objects

BACnet object model: trait, database, and object implementations.

### BACnetObject Trait

```rust
use bacnet_objects::traits::BACnetObject;

// Every object type implements:
trait BACnetObject {
    fn object_identifier(&self) -> ObjectIdentifier;
    fn object_name(&self) -> &str;
    fn object_type(&self) -> ObjectType;
    fn read_property(&self, property: PropertyIdentifier, array_index: Option<u32>)
        -> Result<PropertyValue, Error>;
    fn write_property(&mut self, property: PropertyIdentifier, array_index: Option<u32>,
        value: PropertyValue, priority: Option<u8>) -> Result<(), Error>;
    fn property_list(&self) -> Vec<PropertyIdentifier>;
}
```

The pre-1.0 object API removes `WritePropertyRollback` and the
`capture_write_property_rollback` / `restore_write_property_rollback` hooks.
Implementors validate writes and preserve their own state on failure. The bundled
WritePropertyMultiple service retains every successful prefix write, reports the
first failure, and leaves the remaining suffix unprocessed; it does not restore
previous values. Built-in persistence and File resize candidates retain their
existing commit boundaries. No replacement token API is needed.

For unindexed writes that reach a built-in object's final property dispatch,
absent properties return `PROPERTY/UNKNOWN_PROPERTY`, including NULL writes.
Present read-only properties return `PROPERTY/WRITE_ACCESS_DENIED`. Presence is
based on that instance's effective metadata, including optional properties and
`PROPERTY_LIST`. Unprovisioned Staging names and stream File `RECORD_COUNT`
also report absence; present read-only record File counts remain denied. Earlier
state, command-source, authorization and indexed-write
guards retain their precedence; custom object implementations retain their own
write dispatch. WPM reports the failed coordinate and retains its successful
prefix. See [bounded error evidence](conformance/support-summary.md#ledger-rows).

At the indexed WP/WPM service gate, nonempty effective metadata that omits the
property produces `PROPERTY/UNKNOWN_PROPERTY` before value decoding. A served
scalar or BACnetLIST still produces `PROPERTY/PROPERTY_IS_NOT_AN_ARRAY`; a served
array retains its object-owned element, count and write-access rules. This
absence-first ordering is a local error-precedence policy. Empty custom metadata
does not prove absence: those objects keep their array classifier and writer
delegation. For this early absence failure, WPM keeps its successful prefix and
reports the exact failed object/property/index, without authorizing or observing
the failing element or suffix. The rejected indexed attempt produces no execution
Audit record; present read-only arrays and unindexed absence retain their existing
Audit handling. The outer WP authorization check and direct object writes are
unchanged.

Intrinsic reporting uses one proposal/commit contract. The
`evaluate_intrinsic_reporting` and `tick_intrinsic_reporting` hooks return a
fire-ready `TransitionOutcome` while leaving event state, acknowledgment bits,
history, and the ready proposal unchanged until commit succeeds. Implement
`commit_event_transition_internal` to validate the supplied
`EventTransitionCommit`, atomically apply all object-owned transition state, and
return `EventTransitionCommitError` without mutation on failure. Custom objects
can use these public types directly; the built-in private commit kernel is not
required. Both server paths commit before distribution, even when Event_Enable,
DCC, or an empty recipient list suppresses sending. The default commit hook
returns `Unsupported`; it never authorizes an intrinsic notification.

The pre-1.0 API removes `intrinsic_reporting_requires_atomic_commit` and the
exported `impl_intrinsic_reporting!` macro. Migrate custom objects to the hooks
above; there is no alternate immediate-commit path. Standalone detector
`probe`/`tick` methods retain their own detector-local behavior. Executed evidence
is recorded in `BACNET-13-INTRINSIC-PROPOSAL-COMMIT` in the conformance ledger.

### ObjectDatabase

```rust
use bacnet_objects::database::ObjectDatabase;

let mut db = ObjectDatabase::new();
db.add(Box::new(analog_input));

let obj = db.get(&oid);                // Option<&dyn BACnetObject>
let obj = db.get_mut(&oid);            // Option<&mut dyn BACnetObject>
```

The pre-1.0 database API now returns `&mut dyn BACnetObject` from `get_mut`.
Structural replacement goes through `add`/`remove`; the scoped
`with_object_adapter` callback supports trusted identity-preserving wrappers
without rebinding clocks or changing indexes. It retires polling ownership before
invocation, including callback errors and unwinds, and cannot return a slot borrow.

Trend polling state now belongs to the database; the separate `TrendLogState`
argument is removed. A synchronous database poll selects, reads and appends under
one caller-owned exclusive guard. `Log_Interval` is in hundredths of a second
(raw 1 is 10 ms, raw 50 is 500 ms). Successful attempts anchor the next interval
to actual completion, with no catch-up burst. The server sleeps until the earliest
due time, capped at 100 ms to reconcile changed configuration. Invalid clocks and
insertion errors retry after 100 ms without advancing the last success. An overdue
entry after slow synchronous work yields for 1 ms instead of spinning. These are
local scheduling policies, not hard real-time guarantees. Custom polling callers
must bind the database's monotonic clock as well as its Device clock. The bundled
server binds both. Existing disabled/count-only accepted outcomes still advance
the schedule; remote/indexed reference execution is not added.

### Object Types (62)

#### Core I/O (9)

| Type | Constructor |
|------|-------------|
| `AnalogInputObject` | `::new(instance, name, units)` |
| `AnalogOutputObject` | `::new(instance, name, units)` |
| `AnalogValueObject` | `::new(instance, name, units)` |
| `BinaryInputObject` | `::new(instance, name)` |
| `BinaryOutputObject` | `::new(instance, name)` |
| `BinaryValueObject` | `::new(instance, name)` |
| `MultiStateInputObject` | `::new(instance, name, number_of_states)` |
| `MultiStateOutputObject` | `::new(instance, name, number_of_states)` |
| `MultiStateValueObject` | `::new(instance, name, number_of_states)` |

#### Value Present_Value access

The three Value families also offer `with_access`: Analog Value takes
`(instance, name, units, access)`, Binary Value takes `(instance, name, access)`,
and Multi-state Value takes `(instance, name, number_of_states, access)`.
The final argument is `bacnet_objects::present_value_access::PresentValueAccess`:

| Mode | Network-equivalent Present_Value writes | Local application updates |
| --- | --- | --- |
| `Commandable` (the `new` default) | Sourced priority commands; NULL relinquishes a slot | Use sourced commands through `write_local` |
| `Writable` | Direct replacement; supplied valid priority is ignored | Accepted while in service |
| `ReadOnly` | Denied in service; accepted while Out_Of_Service | Accepted while in service |

For the two noncommandable modes, both `BACnetObject::write_property` and
`write_property_from` enforce the same access and type/range checks. A permitted
NULL write succeeds without changing Present_Value (§19.2); an array index still
fails because Present_Value is not an array. Read-only in-service writes remain
denied, including NULL. Priority_Array, Relinquish_Default, Current_Command_Priority,
Value_Source, Value_Source_Array, Last_Command_Time and commandable-only
Audit_Priority_Filter are absent from these modes' projected metadata. This does
not disable the remaining supported AV/BV target Audit policy or add MSV target
Audit reporting.

`BACnetServer::set_present_value_local` supplies a logical application value to
Analog/Binary/Multi-state Inputs and noncommandable Values, then runs the existing
event and COV path after releasing the database lock. The corresponding low-level
`set_present_value_internal` hook bypasses those server notifications. Both deny
updates while Out_Of_Service to preserve simulation ownership: this is local
policy for Inputs and the object-clause rule for these Values. Application NULL
is an invalid datatype, not a relinquishment. For network-equivalent writes use
`write_local`; noncommandable writes remain available without resolved command
identity. Commandable writes still require a valid source. These access modes are
Rust construction APIs; Python constructors retain their current defaults.

#### Schedule & Notification (5)

| Type | Constructor |
|------|-------------|
| `CalendarObject` | `::new(instance, name)` |
| `ScheduleObject` | `::new(instance, name, default_value)` |
| `NotificationClass` | `::new(instance, name)` |
| `AlertEnrollmentObject` | `::new(instance, name, initial_source)` |
| `EventEnrollmentObject` | `::new(instance, name, event_type)` |

`ScheduleObject::add_object_property_reference` retains a complete local
`BACnetObjectPropertyReference`, including its optional target array index.
The public `BACnetObject::tick_schedule` hook now returns
`Option<(PropertyValue, Vec<BACnetObjectPropertyReference>)>`; custom overrides
must return the full references instead of object/property pairs. Endpoint
forwarding and server execution preserve those coordinates. A failed target
write does not prevent subsequent target writes. The current profile is
local-only, with read-only `Priority_For_Writing` fixed at 16.

`List_Of_Object_Property_References` now reads as `PropertyValue::ApplicationData`
containing concatenated bare context-tagged local DeviceObjectPropertyReference
bodies: object `[0]`, property `[1]`, optional target index `[2]`, and no Device
member. RP and RPM emit these bytes unchanged; an empty list has an empty payload.
The list property itself is not an array, so its own indexed requests still fail
with `PROPERTY_IS_NOT_AN_ARRAY`. This correction adds no source-origin hooks.

`AlertEnrollmentObject::new` now requires the initial
`bacnet_types::primitives::ObjectIdentifier` reported by `Present_Value`.
This is an intentional breaking correction: migrate two-argument callers by
passing the object that most recently provided an alert. Use
`record_alert_source(source)` to update only that source identity; the helper
does not evaluate an alert or update event, timestamp, acknowledgement, or
notification state. The served Table 12-61 surface no longer includes the
previous compatibility-only `Status_Flags`, `Out_Of_Service`, or `Reliability`
properties.

`bacnet_server::event_enrollment::evaluate_event_enrollments_report` returns
one `EventEnrollmentEvaluationReport` containing committed `transitions`,
`reliability_results`, and typed `diagnostics`. `ObservationUnavailable` remains
distinct from an ordinary `NoTransition`, and Reliability commit diagnostics keep
their own stage. `evaluate_event_enrollments` deliberately returns only event
transitions. The pre-1.0 duplicate detailed report API has been removed; use the
unqualified types and complete report entrypoint. The public report contract is
covered by [the external-crate tests](../crates/bacnet-server/tests/event_enrollment_report.rs).

#### Logging & Trending (5)

| Type | Constructor |
|------|-------------|
| `TrendLogObject` | `::new(instance, name, buffer_size)` |
| `TrendLogMultipleObject` | `::new(instance, name, buffer_size)` |
| `EventLogObject` | `::new(instance, name, buffer_size)` |
| `AuditLogObject` | `::new(instance, name, buffer_size, persistence)` |
| `AuditReporterObject` | `::new(instance, name)` |

`TrendLogObject::add_record`, `TrendLogMultipleObject::add_record`, and
`EventLogObject::add_record` return `Result<(), Error>`. Handle or propagate that
result: a required stop-before-full status transition fails atomically with
`DEVICE / OPERATIONAL_PROBLEM` when its clock is missing or invalid. `Ok(())`
means the operation was accepted; disabled logging can ignore the ordinary
record, zero-capacity logging can count without storing it, and a status
transition can replace it.

The pre-1.0 `BACnetObject` contract now has one fallible `add_trend_record` hook.
The void hook and `try_add_trend_record_internal` adapter have been replaced.
Custom implementations return their insertion result directly; the default
returns `OBJECT / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED`. The server poller
retries failed insertions without advancing its last-log time. Bounded evidence
is recorded in `BACNET-12-LOG-STATUS-LIFECYCLE`; complete log-family conformance
is not claimed.

Trusted local configuration through `dyn BACnetObject` uses one atomic
`configure_audit_reporter_internal(level, operations, confirmed, selectors, priorities, maximum_send_delay)`
contract. It replaces all six settings once; invalid or resource-denied changes
leave every field unchanged. The final argument is `Option<AuditSendDelay>`:
`None` omits both delay/control properties, while `Some(AuditSendDelay::new(0)?)`
exposes the pair with immediate delivery. Positive values enable bounded target
batching; see [delay controls and limits](delayed-target-audit.md). Built-in live
setters and Description writes share that boundary and return Result. `None` selectors remove Monitored_Objects and
select all nominal targets; `Some(vec![])` retains an empty property and selects
none. Runtime ownership prepares mandatory change notifications before committing.
The private endpoint source adapter forwards the contract while rejecting a present
delay capability and preserving exactly-one source-role ownership. See
[target Reporter ownership and live changes](target-audit-reporters.md).

#### Building Control (7)

| Type | Constructor |
|------|-------------|
| `LoopObject` | `::new(instance, name, output_units)` |
| `CommandObject` | `::new(instance, name)` |
| `TimerObject` | `::new(instance, name)` |
| `LoadControlObject` | `::new(instance, name)` |
| `ProgramObject` | `::new(instance, name)` |
| `AveragingObject` | `::new(instance, name)` |
| `StagingObject` | `::new(instance, name, StagingConfig { ... })` |

Staging uses an explicit atomic configuration; the former stage-count-only
constructor is intentionally removed because it could not create a valid
ladder or target mapping. To migrate to 0.11.0, replace that argument with a
`StagingConfig` containing the initial value, minimum, units, priority, at least
two ordered stages, and local target references. Each stage's `values` must
have one entry per target; optional `stage_names` must have one name per stage.
Construction returns an error for invalid configuration, so preserve the
fallible result handling:

```rust
use bacnet_objects::staging::{StagingConfig, StagingObject};
use bacnet_types::constructed::{BACnetDeviceObjectReference, BACnetStageLimitValue};
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::ObjectIdentifier;

let target = BACnetDeviceObjectReference {
    device_identifier: None,
    object_identifier: ObjectIdentifier::new(ObjectType::BINARY_OUTPUT, 1)?,
};
let staging = StagingObject::new(
    1,
    "Two-stage fan",
    StagingConfig {
        present_value: 5.0,
        min_present_value: 0.0,
        units: 62,
        priority_for_writing: 8,
        stages: vec![
            BACnetStageLimitValue {
                limit: 10.0,
                values: vec![false],
                deadband: 1.0,
            },
            BACnetStageLimitValue {
                limit: 20.0,
                values: vec![true],
                deadband: 1.0,
            },
        ],
        target_references: vec![target],
        stage_names: Some(vec!["Off".into(), "On".into()]),
    },
)?;
# Ok::<(), bacnet_types::error::Error>(())
```

Staging targets are local-only Binary Output, Binary Value, or Binary Lighting
Output objects. The server applies stage changes through its ordinary local
write notification path at `priority_for_writing`, completing the bounded local
plan during write handling without remote I/O. A target failure sets source
`Reliability` to `UNRELIABLE_OTHER`; a later fully successful current plan
clears it. `Out_Of_Service` decouples targets while preserving PV/stage
evaluation, and returning to service reapplies the selected stage. Network
writes may replace individual or whole `Stages`, `Target_References`, and
configured `Stage_Names` arrays, but array lengths are fixed after construction
so coupled configuration cannot pass through an invalid intermediate shape.
`Max_Pres_Value` is derived from the final stage limit. Staging does not
advertise intrinsic reporting or COV.

#### Lighting & Color (4)

| Type | Constructor |
|------|-------------|
| `LightingOutputObject` | `::new(instance, name)` |
| `BinaryLightingOutputObject` | `::new(instance, name)` |
| `ColorObject` | `::new(instance, name)` |
| `ColorTemperatureObject` | `::new(instance, name)` |

#### Life Safety (2)

| Type | Constructor |
|------|-------------|
| `LifeSafetyPointObject` | `::new(instance, name)` |
| `LifeSafetyZoneObject` | `::new(instance, name)` |

#### Access Control (7)

| Type | Constructor |
|------|-------------|
| `AccessDoorObject` | `::new(instance, name)` |
| `AccessPointObject` | `::new(instance, name)` |
| `AccessCredentialObject` | `::new(instance, name)` |
| `AccessUserObject` | `::new(instance, name)` |
| `AccessRightsObject` | `::new(instance, name)` |
| `AccessZoneObject` | `::new(instance, name)` |
| `CredentialDataInputObject` | `::new(instance, name)` |

#### Transportation (3)

| Type | Constructor |
|------|-------------|
| `ElevatorGroupObject` | `::new(instance, name)` |
| `EscalatorObject` | `::new(instance, name)` |
| `LiftObject` | `::new(instance, name, num_floors)` |

#### Groups & Views (3)

| Type | Constructor |
|------|-------------|
| `GroupObject` | `::new(instance, name)` |
| `GlobalGroupObject` | `::new(instance, name)` |
| `StructuredViewObject` | `::new(instance, name)` |

#### Measurement (2)

| Type | Constructor |
|------|-------------|
| `AccumulatorObject` | `::new(instance, name, units)` |
| `PulseConverterObject` | `::new(instance, name, units)` |

#### System (3)

| Type | Constructor |
|------|-------------|
| `DeviceObject` | `::new(DeviceConfig { .. })` |
| `FileObject` | `::new(instance, name, file_type)` |
| `NetworkPortObject` | `::new(instance, name, network_type)` |

#### Extended Value Types (12)

| Type | Constructor |
|------|-------------|
| `IntegerValueObject` | `::new(instance, name)` |
| `PositiveIntegerValueObject` | `::new(instance, name)` |
| `LargeAnalogValueObject` | `::new(instance, name)` |
| `CharacterStringValueObject` | `::new(instance, name)` |
| `OctetStringValueObject` | `::new(instance, name)` |
| `BitStringValueObject` | `::new(instance, name)` |
| `DateValueObject` | `::new(instance, name)` |
| `TimeValueObject` | `::new(instance, name)` |
| `DateTimeValueObject` | `::new(instance, name)` |
| `DatePatternValueObject` | `::new(instance, name)` |
| `TimePatternValueObject` | `::new(instance, name)` |
| `DateTimePatternValueObject` | `::new(instance, name)` |

---

## bacnet-client

Async BACnet client with transaction state machine, segmentation, and discovery.

### Building a Client

```rust
use bacnet_client::client::BACnetClient;

// Generic builder — accepts any pre-built TransportPort
let client = BACnetClient::generic_builder()
    .transport(transport)
    .apdu_timeout_ms(6000)
    .build()
    .await?;

// BIP-specific builder — constructs BipTransport from interface/port/broadcast
let client = BACnetClient::bip_builder()
    .interface(Ipv4Addr::UNSPECIFIED)
    .port(0)
    .broadcast_address(Ipv4Addr::BROADCAST)
    .build()
    .await?;

// SC-specific builder (requires `sc-tls` feature)
let client = BACnetClient::sc_builder()
    .hub_url("wss://hub:1234")
    .tls_config(tls_config)
    .vmac([0, 1, 2, 3, 4, 5])
    .device_uuid(client_uuid) // Already provisioned and durably stored by the caller.
    .build()
    .await?;
```

Use `bip_builder()` for B/IP, `sc_builder()` for BACnet/SC, or
`generic_builder()` with a prebuilt transport.

### Routed Confirmed-Request Limits

Routed confirmed requests size each outgoing APDU to the smallest applicable
peer, local-transport, and routed-path allowance before registering a
transaction or emitting a frame. The local allowance retains the transport's
live maximum and the current routed destination-header cost. The routed-path
allowance is an NPDU limit: an unknown path starts from a conservative
228-octet NPDU envelope, then subtracts the forwarded header containing both
the destination address and the client's actual local source MAC. For example,
six-octet destination and source addresses leave 207 APDU octets.

Applications with path-specific evidence can configure the NPDU envelope
without changing `ClientConfig`:

```rust
client
    .configure_routed_path_max_npdu(&router_mac, dnet, 1497)
    .await?;

// Restore the conservative unknown-path policy.
client.clear_routed_path_limit(&router_mac, dnet).await?;
```

State is keyed by the immediate router MAC together with DNET. One confirmed
request at a time owns that path; requests through a different router or to a
different DNET remain independent, and direct requests bypass this state. A
matching Reject-Message-To-Network reason 4 completes only the active owner as
`Error::RoutedPathTooLong { dnet }` and records the attempted NPDU length as an
exclusive upper bound. Learned negative evidence lasts for the client lifetime
and has no widening TTL. Both configuration methods wait for an active owner;
configuring replaces the prior value and deliberately resets learned evidence,
while clearing removes configured and learned evidence. Active Clause 19.4
path probing and cache persistence across process restarts are not provided.

The client retains at most 256 routed-path entries. At capacity it
deterministically reclaims the least-recently-used entry only when it has no
configured or learned evidence and its gate has neither an owner nor waiters.
Configured and learned safety evidence is never silently evicted. If no entry
is safely reclaimable, the operation returns
`Error::RoutedPathCapacityExceeded { capacity: 256 }` before TSM registration
or frame emission.

An ambiguously terminated send (including cancellation, timeout, or send
failure) quarantines its path for the configured APDU timeout multiplied by
the configured attempt count. The same-path gate remains exclusive during
that interval, and network controls already observed at ingress before the
next generation activates are discarded using a monotonic ingress sequence.
A source-correlated terminal response after one attempted frame can end the
generation without quarantine; multi-frame or retried generations remain
conservative.

### Property Access

```rust
// ReadProperty
let ack = client.read_property(&mac, oid, PropertyIdentifier::PRESENT_VALUE, None).await?;
let (value, _) = decode_application_value(&ack.property_value, 0)?;

// WriteProperty
let mut buf = BytesMut::new();
encode_property_value(&mut buf, &PropertyValue::Real(72.5));
client.write_property(&mac, oid, PropertyIdentifier::PRESENT_VALUE, None, buf.to_vec(), Some(8)).await?;

// ReadPropertyMultiple
let specs = vec![ReadAccessSpecification { object_identifier: oid, list_of_property_references: refs }];
let ack = client.read_property_multiple(&mac, specs).await?;

// WritePropertyMultiple
let specs = vec![WriteAccessSpecification { object_identifier: oid, list_of_properties: props }];
client.write_property_multiple(&mac, specs).await?;
```

### COV Subscriptions

Single-property `subscribe_cov_property` and `subscribe_cov_property_to_device`
require a `std::num::NonZeroU32` lifetime in seconds; 28,800 seconds and the full
positive `u32` range are accepted. Use their explicit `unsubscribe_...` methods
for cancellation. The typed `SubscribeCOVPropertyRequest::encode` returns `Result`
and validates the entire subscribe/cancel field pairing before appending bytes.
The server rejects a missing member of the confirmed/lifetime pair as
INCONSISTENT_PARAMETERS (the selected syntax interpretation), and paired zero
lifetime as SERVICES/VALUE_OUT_OF_RANGE, before lookup or subscription mutation.
Structural decoding preserves these values so the formal responses remain distinct.
Ordinary `subscribe_cov` retains `None`/zero indefinite lifetime behavior. Its
`SubscribeCOVRequest::encode` also returns `Result`: a present lifetime requires
an explicit confirmed-notification mode, while mode alone is valid. Both absent
means cancellation. Invalid lifetime-only requests leave the output buffer
unchanged; the server returns INCONSISTENT_PARAMETERS before object lookup,
expiry cleanup or subscription changes. Public Rust/Python ordinary subscribe
methods already supply the mode and retain their optional lifetime signatures.
Python exposes ordinary COV and PropertyMultiple, not the single-property API.
These boundaries are tracked in the [COV subscription ledger](conformance/support-summary.md).

The full server owns the served Device execution profile. Every Device's
`Protocol_Services_Supported` reports the fixed `EXECUTED_SERVICES`, with the
existing clock-dependent time-service filter. Both `Active_COV_Subscriptions`
and `Active_COV_Multiple_Subscriptions` are present: the selected lowest Device
gets live lists and other Devices get empty lists. Network RP, budgeted RPM,
`read_local` and `generate_pics` share effective Device definitions, including
Property_List, ALL/OPTIONAL/REQUIRED classification and array-index behavior.
Normal public Device profile mutation, same-OID replacement and custom object
readers cannot change this served contract. Other properties retain their object
behavior. WP, WPM and network-equivalent `write_local` reject writes to Device
`Protocol_Services_Supported`, both COV lists and `Property_List` before calling
a custom writer. Existing object/index/value validation and authorization remain
in force; WPM retains its successful prefix and first failed write coordinate.
Direct object/database mutation remains the raw declaration boundary. Device
membership changes still do not rebind discovery identity.

`DeviceObject::set_services_supported` is a standalone declaration, not a
runtime service toggle. Raw built-in Device metadata and reads include property
152 only for declared SubscribeCOV or SubscribeCOVProperty, and property 481
only for declared SubscribeCOVPropertyMultiple; present standalone lists are empty.
Direct database reads, context-free `handle_read_property`/`handle_read_property_multiple`
and standalone `PicsGenerator` use raw object declarations. Use the full server's
read and PICS methods for its execution view.

PICS property rows aggregate all configured instances of each object type in
ascending property-ID order, including single-instance output. A row or read/write
flag means at least one instance supports it; actual access still depends on the
concrete object. A property is optional only when all of its present metadata rows
are optional; a required declaration wins, and absent rows do not vote. For example,
a writable stream File contributes writable File_Size while a writable record File
contributes writable Record_Count. Each served Device passes through the execution
view before this union. Type-level createable/deleteable flags and runtime File
behavior are unchanged. Generated PICS remains draft internal support evidence.

The bundled server keeps ordinary object, Single-property and Multiple-reference
subscriptions independent. All families identify the original BACnet client address
(local MAC or routed SNET/SADR), independently of the immediate router. Ordinary
and Single keys additionally identify process and monitored object; Single also
includes property and array index. Absent, zero and element indexes differ.
Confirmed mode is mutable for ordinary/Single renewal; Multiple includes form in
its context identity, so its two forms coexist.

Each successfully admitted ordinary/Single renewal selects its proposed delivery
route and terms. This includes already-permitted ordinary indefinite renewals;
Single still requires a positive finite lifetime on the wire. Cancellation through
either router removes the canonical context. Refused renewal preserves the live
target's route, terms and paired observation. Each accepted renewal replaces its
generation and resets its observation through the normal initial-notification path;
stale work cannot complete into the replacement. Already admitted old-route work
may finish, and confirmed observations still commit at admission rather than ACK.
Exact duplicates in a Multiple request use the last options once, with quota and
generation capacity reserved before any accepted context refresh.

The latest successfully admitted finite Multiple request sets the current delivery
route, lifetime and delay for every retained reference. An empty finite renewal
updates an existing context but creates none. Cancellation through either router
removes canonical targets without retargeting survivors. Rejected admission preserves
the live target context; unrelated expired-entry purging and counters may still run.
Changing route preserves unreplaced selected-value/flags observations and reference
generations, while a private route ownership token fences every old-route snapshot.
The routed address is a claimed protocol identity, not authentication; existing
mutation authorization still precedes subscription handling.

The pre-1.0 Rust API shares `CovRecipient` between subscription identity and
quota/notification accounting. It replaces the former `MultipleRecipient` and
`CovPeerKey` types without aliases. `CovSubscriptionKey::{Object, Property}` and
`MultipleContextKey` use a `recipient` field; `CovSubscription::recipient()` returns
the canonical address. `CovPolicy::reserved_recipients` holds explicitly reserved
canonical recipients (the existing `reserved_peers` remains a direct-MAC policy).
Table admission rejects routed recipients with an empty source MAC, just as NPDU
source decoding does, before purging or modifying subscriptions. Invalid routed
input is never reinterpreted as a direct peer.

`subscribe_multiple` takes an explicit `&SubscriberEndpoint` route after the context
argument and validates it against the recipient and proposals.
`CovSubscription::endpoint()` on subscription data (also available through accepted
snapshots) reports its captured delivery route.

The public `CovSubscriptionTable` accepts proposed `CovSubscription` values through
fallible `subscribe`/`subscribe_multiple` methods and returns immutable
`CovSubscriptionSnapshot` values. Lookup/cancellation use `CovSubscriptionKey`;
completion takes the accepted snapshot, so an old initial or fanout completion
cannot overwrite a renewed/recreated subscription. Checked generation exhaustion
returns RESOURCES/NO_SPACE_TO_ADD_LIST_ELEMENT before live state changes;
cancellation remains available. `CovTimeRemaining::at(expiry, now)` distinguishes
indefinite, positive finite and expired lifetimes. Positive finite fractions round
up, saturating at `u32::MAX`; only indefinite state projects to wire zero. This is
our local representation policy, not a Standard-prescribed rounding formula.
`CovSubscriptionTable::remaining_lifetime(snapshot, now)` checks the captured
owner/key/generation/route authority and resolves the live expiry, including context-only renewal.
Initial and later notifications recheck eligibility after property reads and before
fresh admission. This is a point-in-time check, not byte retraction if cancellation
races afterward. Multiple retains only values with their own current authority;
a failed live read cannot authorize a stale sibling's payload or companion.
Already admitted confirmed notifications retain their APDU and retry/ACK lifecycle.
`BACnetServer::remove_peer_subscriptions` removes
only entries using the exact current immediate endpoint plus routed source; cleanup
of an obsolete router does not remove migrated subscriptions. Canonical recipient
accounting does not grant cleanup authority to an obsolete route.

Property subscriptions now prepare one selected-coordinate `CovSample` for comparison,
wire payload and fenced baseline completion; a failed selected read or encoding
never substitutes Present_Value. The pre-1.0 table API uses `last_notified_observation: Option<CovObservation>`
with completion owned internally by the notification executor. The former public
`set_last_notified_observation` bypass is removed. Each observation pairs
a required `CovSample` with compact absent/present flags.
`CovObservation::new(sample, flags)` validates present flags; private immutable
fields expose `sample()` and `status_flags()` (the four used bits).
`CovSample::new(&value)` is fallible;
its private immutable storage is normalized and shared by snapshot clones. It
bounds retention before copying/recursive encoding to 32 nested List levels
(root List is level 1), 1,024 nodes including empty Lists, and 65,536 scalar/raw
payload bytes. These local caps remain active under `CovPolicy::unlimited()`;
they do not constrain allocations inside a custom object's read callback.
Admission-time overflow returns RESOURCES/NO_SPACE_TO_ADD_LIST_ELEMENT before
replacement/context refresh. A later unavailable or oversized value is skipped
without advancing its baseline. Independent notification traffic budgets remain.

Unconfirmed notification preparation reserves a checked, nonwrapping ticket only
for a complete eligible observation, before later waits. Each live reference
retains one last-successful marker: successful sends atomically advance that
marker and the entire observation only when their ticket is newer. A failed,
cancelled or refused newer send does not block an older successful send. This
local policy covers ordinary, Single and Multiple reports, including specialized
Value_Source tuples; overlapping companions never complete unqualified references.
Existing owner, generation, route and lifetime fences still apply. Same-route
Multiple expiry refresh retains progress; reference replacement resets it.
Ticket exhaustion suppresses further unconfirmed candidates for that table.
Confirmed reports retain their admission-time baseline and consume no tickets.

This orders prepared observations, not original object mutations, transport byte
order or remote receipt. In particular, a retained Binary Lighting terminal
snapshot prepared after a newer live report may become the baseline even though
its object state is older. Untimestamped reports have no event-time history or
replay guarantee.

Timestamped SubscribeCOVPropertyMultiple references (§13.16.3.1.2.3) record each
qualifying change together with the Device clock frame of its commit. The capture
runs under the database write guard of network WriteProperty, `write_local`,
Binary Lighting terminal transitions, committed intrinsic transitions (both
write-triggered and those confirmed by the periodic Time_Delay task),
fault-detection reliability changes and schedule writes. Changes queue
per reference until a notification carrying them is transmitted. Any notification
to a context also carries the pending changes of that context's other references
(§§13.17.1.1, 13.18.1.1), and each value carries its own `Time_Of_Change`.
Earlier changes of a reference come first, in capture order, as repeated
coordinates. Its latest change then merges with untimestamped current values under
the existing one-value-per-coordinate rules. A coordinate explicitly subscribed
without timestamps is never repeated as history; as before, an unqualified explicit
selector does not remove a companion's time from its current row. The header timestamp names
the latest timestamped change conveyed. The initial report after admission or
re-subscription is stamped with the Device time of admission; this is a local
convention, since no change has been observed yet. A renewal keeps changes not yet
conveyed, including those of a notification that fails during the renewal.

Local bounds deviate from the Standard's expectation of additional notifications
rather than loss (§13.1, §13.18.1.1). One context's pending changes are limited to
an estimate of what one notification of the server's `max_apdu_length` can carry;
on overflow the oldest change of the same reference is dropped first, then the
oldest in the context. Before sending, queued history is trimmed, oldest first, to
fit the encoded request into the local maximum APDU. A reference's latest change is
never dropped, so latest changes plus untimestamped values can still exceed it.
Changes returned by a failed notification wait while a newer change of the same
reference is in flight; once a newer change is transmitted, older ones are dropped
rather than delivered as stale state. These drops increment
`CovCounters::timed_changes_dropped` and log a warning. The subscriber's own
maximum APDU is not consulted. `CovSubscriptionTable::with_max_apdu_length` sets
the bound (the full server uses its configured capacity).

WritePropertyMultiple, staging and source-completion writes are not captured yet,
and neither are Life Safety objects on any path. Their changes still report through the builder's
current-state fallback, stamped when the notification is prepared (#856).
`Max_Notification_Delay` remains reported but not acted on.

Background commits fan COV out as a network write does, once their database guard
is dropped, to ordinary, SubscribeCOVProperty and Multiple subscribers alike: the
periodic intrinsic task's transitions (after their event notifications),
fault-detection reliability changes and schedule writes to controlled objects. Life
Safety objects report exactly the properties the pass changed. The bundled Event
Enrollment objects accept no COV subscriptions, so their periodic evaluation fans
nothing out. The usual COV criteria and DCC suppression apply. The criteria report
only an actual change: a missing or non-positive COV increment means any change,
and a value equal to the last one sent is not reported again, however often its
object is fanned out, unless a Status_Flags change carries it.

The built-in commandable objects expose `Priority_Array` as read-only (§19.2.1).
Set or relinquish a priority slot by writing a value or NULL to `Present_Value`
with the desired priority. Whole-array and indexed `Priority_Array` writes are
denied, including index 0 (the element count); indexed reads remain available.
A refused direct array write does not change the effective value or terminate
an active lighting operation. WPM preserves valid earlier writes when it reaches
such a denied element. This does not impose a write policy on custom objects.

The selected local property profile compares Real, Double, Signed and Unsigned
values in their own types. Only numeric Present_Value inherits the object's
COV_Increment when omitted; other numeric coordinates without an increment report
actual value changes. Integer deltas remain exact, including large Unsigned64
values. Actual array index zero reports count changes and ignores increments.
Positive numeric slots use their own delta; Null and numeric-type transitions
report without coercion. Structured non-array values and reviewed whole
Property_List, Priority_Array, State_Text, Event_Time_Stamps and
Event_Message_Texts coordinates use typed structural equality and ignore
increments. Support follows the reviewed object/property matrix, not the current
numeric appearance of List children. Unclassified whole arrays are refused with
PROPERTY/NOT_COV_PROPERTY whether an increment is present or absent. Indexed
non-arrays that pass existing read validation return PROPERTY_IS_NOT_AN_ARRAY.

For matching finite numeric values, nonpositive increments (including negative
infinity) report any change, and an unchanged value reports nothing; NaN and
positive infinity increments do not trigger numeric deltas. Initial reporting and type transitions still
report. Same-type nonfinite samples compare IEEE bits; identical NaN payloads and
infinities are stable. Structural equality also preserves float bits, while finite
numeric signed zeros compare equal. These are explicit local exceptional-value
policies, not Standard-prescribed arithmetic. Ordinary whole-object values follow
the same rule (#889): a numeric Present_Value must move by the increment, and a
non-numeric or increment-less one must change. Life Safety committed-delta
triggers and confirmed-admission versus unconfirmed-success baseline timing are
preserved.

Applicable Status_Flags changes independently trigger ordinary and property COV.
Property reports include the selected value and declared-present flags; explicit
flags appear once and Multiple emits one companion per retained object. Effective
`property_list()` declares presence. Present flags must be a one-byte BitString
with `unused_bits = 4` and zero unused low bits. Selected read/encoding/cap failure
or declared-present flags failure skips the whole observation, including ordinary
Present_Value: no partial flags-only report and no baseline advance. This transient
failure policy is local. An absent companion is distinct from no delivered baseline;
a later present value can trigger, disappearance alone cannot. A successful
selected-value report while absent records absence. An unreported absent-and-same-
value-return cycle is not tracked.

Multiple reads flags once per object **within each notification context**, pairing
selected values under the same DB/snapshot borrow, then releasing it before
transport. Separate contexts may sample at different times; custom interior-mutability
callbacks are not promised atomic hardware sampling. Only references surviving
late lifetime/ownership checks authorize companions, timestamps and paired baseline
completion. Ordinary nonnumeric/no-increment values report only on change (#889).

This profile does not add empty finite Multiple contexts, delayed Multiple
notifications, live Device subscription-property projection, general numeric
whole-array reduction or specialized object-specific report sets.


```rust
// Subscribe to one property with an explicit finite lifetime.
client.subscribe_cov_property(&mac, CovPropertySubscription {
    subscriber_process_identifier: process_id,
    monitored_object_identifier: oid,
    monitored_property_identifier: PropertyIdentifier::PRESENT_VALUE,
    monitored_property_array_index: None,
    confirmed: false,
    lifetime: std::num::NonZeroU32::new(28_800).unwrap(),
    cov_increment: Some(0.5),
}).await?;
client.unsubscribe_cov_property(&mac, process_id, oid,
    PropertyIdentifier::PRESENT_VALUE, None).await?;

// Ordinary object subscription follows its separate lifetime rules.

// Subscribe
client.subscribe_cov(&mac, process_id, oid, true, Some(300)).await?;

// Subscribe to multiple properties at once
let cov_specs = vec![COVSubscriptionSpecification {
    monitored_object_identifier: oid,
    list_of_cov_references: vec![COVReference {
        monitored_property: PropertyReference {
            property_identifier: PropertyIdentifier::PRESENT_VALUE,
            property_array_index: None,
        },
        cov_increment: Some(0.5),
        timestamped: true,
    }],
}];
let request = SubscribeCOVPropertyMultipleRequest {
    subscriber_process_identifier: process_id,
    issue_confirmed_notifications: true,
    lifetime: Some(300),
    max_notification_delay: Some(10),
    list_of_cov_subscription_specifications: cov_specs,
};
let mut service_data = bytes::BytesMut::new();
request.encode(&mut service_data)?;
client
    .confirmed_request(
        &mac,
        ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE,
        &service_data,
    )
    .await?;

// Receive notifications (broadcast channel — multiple consumers OK)
let mut rx = client.cov_notifications();
let notification: COVNotificationRequest = rx.recv().await?;

// Unsubscribe
client.unsubscribe_cov(&mac, process_id, oid).await?;
```

`SubscribeCOVPropertyMultipleRequest::encode` is fallible and validates the entire
request before appending bytes. Invalid timing pairs, empty nested reference lists,
prohibited property selectors and the cumulative reference limit return
`Error::Encoding` without changing the destination buffer. The former `try_encode`
and panicking `encode` split has been removed. An empty outer list remains encodable
with omitted or valid finite timing; finite empty encoding does not establish that
the bundled server materializes an empty subscription context.

### Discovery

```rust
client.who_is(None, None).await?;                       // broadcast
client.who_has(WhoHasObject::Name("Zone Temp".into()), None, None).await?;

let devices = client.discovered_devices().await;         // Vec<DiscoveredDevice>
let device = client.get_device(1234).await;              // Option<DiscoveredDevice>
client.clear_devices().await;                            // reset table
```

### Device Management

```rust
client.device_communication_control(&mac, EnableDisable::DISABLE, Some(60), Some("password".into())).await?;
client.reinitialize_device(&mac, ReinitializedState::WARMSTART, None).await?;
```

### Object Management

```rust
client.create_object(&mac, ObjectSpecifier::Type(ObjectType::ANALOG_INPUT), initial_values).await?;
client.delete_object(&mac, oid).await?;
```

### Alarms & Events

```rust
client.acknowledge_alarm(&mac, process_id, oid, event_state, "operator").await?;
let raw = client.get_event_information(&mac, None).await?;
let raw = client.get_alarm_summary(&mac).await?;
let raw = client.get_enrollment_summary(&mac, ack_filter, event_state, event_type, min_pri, max_pri, notif_class).await?;
```

### Life Safety

```rust
client.life_safety_operation(&mac, process_id, "operator", LifeSafetyOperation::SILENCE, Some(oid)).await?;
```

### File Services

```rust
let access = FileAccessMethod::Stream { file_start_position: 0, requested_octet_count: 1024 };
let raw = client.atomic_read_file(&mac, file_oid, access.clone()).await?;
let ack = client.atomic_read_file_decoded(&mac, file_oid, access).await?;
client.atomic_write_file(&mac, file_oid, FileWriteAccessMethod::Stream { file_start_position: 0, file_data: data }).await?;
```

`atomic_read_file` remains the compatibility API for the raw encoded ACK payload.
`atomic_read_file_decoded` performs one request, decodes its `AtomicReadFileAck`,
and validates that the ACK access arm matches the request and does not exceed
the requested window. It does not iterate an entire file.

### ReadRange

```rust
let ack = client.read_range(&mac, oid, PropertyIdentifier::LOG_BUFFER, None, Some(RangeSpec::ByPosition { reference_index: 1, count: 10 })).await?;
```

### List Manipulation

```rust
client.add_list_element(&mac, oid, PropertyIdentifier::OBJECT_LIST, None, element_bytes).await?;
client.remove_list_element(&mac, oid, PropertyIdentifier::OBJECT_LIST, None, element_bytes).await?;
```

### Private Transfer

```rust
let raw = client.confirmed_private_transfer(&mac, vendor_id, service_number, Some(params)).await?;
client.unconfirmed_private_transfer(&mac, vendor_id, service_number, Some(params)).await?;
```

### Text Messages

```rust
let raw = client.confirmed_text_message(&mac, device_oid, priority, "Fire alarm", class_type, class_value).await?;
client.unconfirmed_text_message(&mac, device_oid, priority, "Status update", None, None).await?;
```

### Write Group and Who-Am-I

The client has no dedicated methods for these services. Build the
`bacnet_services` request and send it through the generic unconfirmed-request API.

```rust
use std::num::NonZeroU32;

use bacnet_services::who_am_i::WhoAmIRequest;
use bacnet_services::write_group::{GroupChannelValue, WriteGroupRequest};
use bacnet_types::enums::UnconfirmedServiceChoice;
use bytes::BytesMut;

// Channel 5 gets REAL 72.0; channel 6 gets NULL at priority 10.
let request = WriteGroupRequest {
    group_number: NonZeroU32::new(1).unwrap(),
    write_priority: 8,
    change_list: vec![
        GroupChannelValue {
            channel: 5,
            override_priority: None,
            value: vec![0x44, 0x42, 0x90, 0x00, 0x00],
        },
        GroupChannelValue {
            channel: 6,
            override_priority: Some(10),
            value: vec![0x00],
        },
    ],
    inhibit_delay: Some(false),
};
let mut service_data = BytesMut::new();
request.encode(&mut service_data)?;
client.unconfirmed_request(&mac, UnconfirmedServiceChoice::WRITE_GROUP, &service_data).await?;

// Who-Am-I is usually broadcast.
let who_am_i = WhoAmIRequest {
    vendor_id: 260,
    model_name: "Controller-X".into(),
    serial_number: "SN-0001".into(),
};
let mut service_data = BytesMut::new();
who_am_i.encode(&mut service_data)?;
client.broadcast_unconfirmed(UnconfirmedServiceChoice::WHO_AM_I, &service_data).await?;
```

### Virtual Terminal

The client has no VT-specific methods. Build the `bacnet_services` request and
send it with `confirmed_request`. VT-Open carries both the terminal class and
the caller's own session number (Clause 17.2.1); VT-Close needs at least one
identifier and `encode` returns an error for an empty list; the VT-Data flag
goes out as an Unsigned 0 or 1; and a VT-Data ACK is either `AllAccepted` or
`Partial` with the accepted octet count (Clause 17.4.1.2).

```rust
use bacnet_services::virtual_terminal::{
    VTCloseRequest, VTDataAck, VTDataRequest, VTOpenAck, VTOpenRequest,
};
use bacnet_types::enums::{ConfirmedServiceChoice, VTClass};
use bytes::BytesMut;

let mut buf = BytesMut::new();
VTOpenRequest {
    vt_class: VTClass::DEFAULT_TERMINAL,
    local_vt_session_identifier: 5,
}
.encode(&mut buf);
let raw = client
    .confirmed_request(&mac, ConfirmedServiceChoice::VT_OPEN, &buf)
    .await?;
let remote_id = VTOpenAck::decode(&raw)?.remote_vt_session_identifier;

let mut buf = BytesMut::new();
VTDataRequest {
    vt_session_identifier: remote_id,
    vt_new_data: b"hello".to_vec(),
    vt_data_flag: false,
}
.encode(&mut buf);
let raw = client
    .confirmed_request(&mac, ConfirmedServiceChoice::VT_DATA, &buf)
    .await?;
match VTDataAck::decode(&raw)? {
    VTDataAck::AllAccepted => {}
    VTDataAck::Partial { accepted_octet_count } => {
        // Resend the octets after the first `accepted_octet_count`.
        let _ = accepted_octet_count;
    }
}

let mut buf = BytesMut::new();
VTCloseRequest {
    list_of_remote_vt_session_identifiers: vec![remote_id],
}
.encode(&mut buf)?;
client
    .confirmed_request(&mac, ConfirmedServiceChoice::VT_CLOSE, &buf)
    .await?;
```

### Audit Services

Audit `target_value` and `current_value` distinguish `None` (absent) from
`Some(Vec::new())` (present empty, such as an empty list). Both codecs retain
that distinction; encoded NULL remains a separate one-octet value. Structurally
valid values above 32 octets are permitted by the codec. Target Reporters
include complete known values of 0–32 encoded octets and omit larger values
whole under the existing local inclusion policy.

```rust
use bacnet_services::audit::{
    AuditLogQueryAck, AuditLogQueryRequest, AuditNotificationRequest,
};
use bacnet_types::enums::{ConfirmedServiceChoice, UnconfirmedServiceChoice};
use bytes::BytesMut;

let notification_request: AuditNotificationRequest = /* build typed request */;
let mut service_data = BytesMut::new();
notification_request.try_encode(&mut service_data)?;
client.confirmed_request(
    &mac,
    ConfirmedServiceChoice::CONFIRMED_AUDIT_NOTIFICATION,
    &service_data,
).await?;

client.unconfirmed_request(
    &mac,
    UnconfirmedServiceChoice::UNCONFIRMED_AUDIT_NOTIFICATION,
    &service_data,
).await?;

let query_request: AuditLogQueryRequest = /* build typed request */;
let mut query_data = BytesMut::new();
query_request.try_encode(&mut query_data)?;
let raw_ack = client.confirmed_request(
    &mac,
    ConfirmedServiceChoice::AUDIT_LOG_QUERY,
    &query_data,
).await?;
let query_ack = AuditLogQueryAck::decode(&raw_ack)?;
```

These remain generic-client examples. The bundled server executes
AuditLogQuery against the retained in-memory snapshot of an explicitly backed
`AuditLogObject`, returning newest-first typed records through the existing
ComplexACK segmentation path. ConfirmedAuditNotification and
UnconfirmedAuditNotification receipt are available only when the server is
configured with exactly one `audit_notification_sink` and the corresponding
fast `audit_notification_authorizer` or
`unconfirmed_audit_notification_authorizer`; missing, false, or panicking
policy fails closed. Each policy receives the immediate MAC, optional routed
NPDU source, configured sink, and decoded request separately from the
peer-reported payload; only the confirmed context has an invoke ID. Accepted
lists merge or create records atomically through the sink's durable backend.
For the built-in `AuditLogObject`, a successful confirmed receipt also stores
its complete exact-request identity and Unix UTC completion timestamp in that
same snapshot transaction. The 60-second / 256-entry ledger survives a reopen;
retained duplicates are discarded before authorization without a SimpleACK
replay. Entries expire at 60 seconds, and a stored future timestamp fails open
rather than suppressing indefinitely. The general process-local confirmed-
request tracker remains the pending/session guard.

`AuditLogSnapshot::completed_receipts` is part of the public custom-persistence
snapshot contract. `FileAuditLogPersistence` writes schema v2, reads schema v1
as an empty receipt ledger, rejects unknown future versions, and retains the
existing two-slot generation/checksum recovery policy. When migrating a custom
`AuditLogPersistence` implementation to 0.11.0, add `completed_receipts: Vec::new()`
to newly constructed snapshots and when decoding an older format without
receipts. Thereafter, `commit` must durably store the supplied receipt ledger
and records in the same atomic snapshot, and `load` must restore both. Dropping
or separately committing the ledger loses confirmed-request duplicate
protection after a reopen. The built-in file backend needs no separate v1
conversion: it writes v2 on the next successful commit.

Back up both `.slot0` and `.slot1` files before the first v2 commit. A reader that
supports only v1 cannot read v2 snapshots; rolling back to such an implementation
requires restoring a compatible backup and loses changes made after that backup.

Unconfirmed receipt never emits a response and never writes the confirmed ledger.
Synchronous persistence under the database writer is an intentional availability
limitation. Query authorization, sustained rate limiting, and multi-log routing
policy are not provided. The standalone server optionally forwards changed
accepted batches from its selected log after local commit: configure
`AuditLogObject::set_member_of` and a remote configured `DeviceBinding`.
This is one best-effort confirmed attempt, not durable forwarding; restart can
lose send progress. See [Audit Log forwarding](audit-log-forwarding.md) for
properties, failure behavior, resource bounds, and exclusions.
Query input changes never rewrite stored notifications or receipt identities,
and the requested-count, ACK-cap, and segmentation limits stay independent.
Executed-service bit 46
represents receipt only; no Audit Reporting BIBB, including AR-L-A, is claimed.

---

## bacnet-server

Async BACnet server that hosts objects and dispatches incoming requests.

### Server shutdown and local sends

`BACnetServer::stop()` seals new local broadcasts and mutations, joins admitted
server work, then stops the owned network and transport before returning success.
The target-Audit drain retains the ingress needed for acknowledgments until its
existing completion/deadline boundary. Cancelling a stop waiter retains cleanup:
call `stop()` again to join it. Transport cleanup errors retain the owner for retry;
a cleanup-task panic remains an error on later calls.

`broadcast_i_am()` and cloned `IAmBroadcaster` handles share a fail-fast limit of
32 local sends in flight, independent of inbound peer quotas. An admitted send is
server-owned even if its caller stops waiting. Shutdown cancels and joins it;
retained handles reject new sends and do not prolong the transport lifetime.
Local mutation methods reject before changing objects once shutdown starts.
`read_local()`, PICS, counters and database inspection remain available after
Rust server stop. `local_mac()` retains the last bound address snapshot; it does
not assert that the transport remains active.

Drop seals admission and aborts owned application work. It does not synchronously
join task destruction. If transport cleanup has already begun, that owned task
continues while the runtime runs. Use awaited `stop()` for the joined resource
release guarantee. This is a local lifecycle contract, not a BACnet wire change.

### Confirmed transaction lifetimes

Current source detects exact ordinary confirmed duplicates only while their
server transaction is pending. Once an unsegmented SimpleACK, ComplexACK, Error,
Reject or Abort is encoded and its local network send is issued, the same peer,
Invoke ID and bytes may execute again. The boundary precedes the transport
future's eventual result; it establishes neither physical emission nor peer
receipt. MS/TP uses the synchronous encoded reply-channel handoff. Failed
encoding, failed handoff, cancellation and discarded work release ownership.

A segmented ComplexACK transfers ownership to its response child before the
request handler returns; the child may outlive that handler. It remains pending through the final SegmentACK or
until terminal Abort, timeout, send failure or cancellation. A generated terminal
Abort retires the transaction at local Abort issuance. Task and segmented-send
capacity permits keep their own lifetimes, so a newly reusable Invoke ID may
still encounter the normal resource limit while older send work is active.

Detection remains bounded to 256 pending entries and 64 KiB of service-request
bytes per tracked entry. Requests beyond those detection bounds proceed through
normal service admission. Local peers retain canonical MAC keys; valid routed
peers retain SNET/SADR keys across router changes. Accepted direct SC also retains
the immutable leaf/incarnation partition described above. There is no generic
completed cache or response replay. LifeSafetyOperation's separate completed
replay policy and Audit service receipts are unchanged.

This behavior postdates published 0.11.0. `NetworkLayer::send_apdu_on_issuance`
provides the narrow post-NPDU-encoding callback used by these response owners;
constructing its lazy future does not invoke the callback. This does not resolve
response socket affinity or segmented-response ACK/Abort confinement (#524).
See the [bounded TSM evidence](conformance/standard-135-2020-ledger.md#ordinary-confirmed-transaction-lifetimes).

### Building a Server

```rust
use bacnet_server::server::BACnetServer;

// Generic builder — accepts any pre-built TransportPort
let server = BACnetServer::generic_builder()
    .database(db)
    .transport(transport)
    .build()
    .await?;

// BIP-specific builder — constructs BipTransport from interface/port/broadcast
let server = BACnetServer::bip_builder()
    .database(db)
    .interface(Ipv4Addr::UNSPECIFIED)
    .port(0xBAC0)
    .broadcast_address(Ipv4Addr::BROADCAST)
    .life_safety_operation_authorizer(|context| {
        // Use authenticated deployment identity where available; the
        // Requesting Source string is peer-controlled descriptive text.
        allowed_life_safety_peer(&context.source_mac, context.source_network.as_ref())
    })
    .build()
    .await?;

// SC-specific builder (requires `sc-tls` feature)
let server = BACnetServer::sc_builder()
    .database(db)
    .hub_url("wss://hub:1234")
    .tls_config(tls_config)
    .vmac([0, 1, 2, 3, 4, 5])
    .device_uuid(server_uuid) // Already provisioned; distinct from the client's UUID.
    .build()
    .await?;

// Access the database at runtime
let db = server.database().lock().await;
let value = db.get(&oid).unwrap().read_property(pid, None)?;

// Check communication state
let state = server.comm_state(); // 0=Enable, 1=Disable, 2=DisableInitiation

// Stop
server.stop().await?;
```

Use `bip_builder()` for B/IP, `sc_builder()` for BACnet/SC, or
`generic_builder()` with a prebuilt transport.

All three Rust builders accept `.mutation_authorizer(|context| ...)`, also
available as `ServerConfig::mutation_authorizer`. It covers only confirmed
WriteProperty, WritePropertyMultiple, CreateObject, DeleteObject, AddListElement,
RemoveListElement, AtomicWriteFile, SubscribeCOV, SubscribeCOVProperty, and
SubscribeCOVPropertyMultiple. **Omitting it allows existing behavior**, unlike
Audit/LifeSafety's fail-closed absence. False or panic returns
`SERVICES / SERVICE_REQUEST_DENIED` without the denied mutation. WPM authorizes
each element in order and retains an authorized prefix on later denial or
malformed input; other covered services authorize once after service decoding.
Callbacks must be fast, nonblocking, and side-effect-free. Context addresses and
process IDs are claimed, not authenticated identities. DCC/Reinit, Audit/LifeSafety,
reads, discovery, unconfirmed services, and trusted local writes are unchanged.

Each decision context also carries the reassembled ingress snapshot
(`provenance: TransportProvenance`) and the derived channel/relay scope
(`trust: MutationTrust`, mirroring RB-09 `ControlTrust`): `Unverified`,
`VerifiedChannel` (SC-TLS channel), or `VerifiedRelay` (SC-hub relayed
origin). These enums are scope-only; `context.direct_sc_identity()` separately
exposes the [accepted-direct leaf/incarnation](#accepted-direct-tls-identity).
Baseline-only profile: an unknown
origin — including a hub-mediated unknown leaf, which arrives unverified —
never satisfies a baseline-only allow rule, and receive-permission is never
write-permission; the callback owns the rule. Context `Debug` is redacted
(address lengths and target kind only, no MAC bytes or decoded inputs), and
decision counters retain no per-source state. The callback runs after
validation and before mutation; denials perform no database mutation, no
COV/event fan-out, and no audit-log write (counters and bounded diagnostics
only). This policy governs standalone-server mutations; direct handler calls
and trusted local writes stay outside it. The shared endpoint's narrow
[Device-write authorizer](#authorized-endpoint-device-writes) is configured
separately. Python exposes the same native static policy through
`BACnetServer(..., mutation_policy="permissive" | "deny_all")`, without a Python
authorizer callback. See
[Local mutation authorization](mutation-policy.md).

### Life Safety execution and COV

Inbound LifeSafetyOperation is fail-closed unless an authorizer is configured.
The built-in Life Safety Point and Zone objects execute the six silence and
unsilence operations. `RESET`, `RESET_ALARM`, and `RESET_FAULT` execute only
through a configured application-owned Point/Zone reset executor after exact
`Operation_Expected` arming; omitted commit fields remain unchanged and no
physical state is inferred. Exact confirmed duplicates receive the byte-identical
recorded response from the bounded process-local request tracker (60-second /
256-entry retention; requests over 64 KiB execute untracked), so irreversible
actuation still requires application-owned idempotency across tracker expiry
or restart.

Trusted runtime logic can arm or rearm a Life Safety object through
`BACnetServer::set_life_safety_operation_expected_local`. The lower-level
`BACnetObject::set_life_safety_operation_expected_internal` channel also remains
available to custom database owners. Protocol WriteProperty and
WritePropertyMultiple cannot forge `Operation_Expected` or `Silenced`.

`BACnetObject::apply_life_safety_operation` returns
`Result<LifeSafetyOperationOutcome, Error>`: an effect plus exact committed
property changes in stable reporting order, with no duplicates. Custom objects
own this projection. `AlreadyApplied` means no state changed and carries no
deltas; errors leave object state unchanged. The default hook explicitly returns
`OBJECT / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED`.

This pre-1.0 API replaces the coarse return value and removes
`apply_life_safety_operation_detailed`; implementations and callers migrate to
the sole outcome-bearing hook. The built-in Point/Zone reset executors, exact
arming, and existing delta calculation retain their behavior. The former public
server `handle_life_safety_operation` helper is removed; use the object hook for
local execution or the client service API for wire requests. Confirmed dispatch
uses one internal handler retaining exact COV changes, including successful
operations whose only changes are private state and have no COV properties.
The bundled server uses those deltas, trusted rearm readback, and exact WP/WPM/
`write_local`/live-Schedule pre/post readback to route Life Safety COV after
unlocking and after the service ACK where applicable.
Whole-object reports are exactly `Present_Value` plus `Status_Flags` and trigger
only when either changes. Property reports are the subscribed property plus one
`Status_Flags` and trigger when either changes. Point property COV supports
`Present_Value`, `Status_Flags`, `Tracking_Value`, `Silenced`, and
`Operation_Expected`; Zone supports the same set without its unmodeled
`Tracking_Value`, which is rejected with `PROPERTY / NOT_COV_PROPERTY`.
Low-level object setters still bypass server notification ownership.

This is a bounded operational-state slice with pinned partial metadata (Point
`POINT_BASE` 17 rows, Zone `ZONE_BASE` 14 rows; exact PICS projection tests) and
network read-only `Silenced`/`Operation_Expected`; not complete Life Safety
Point/Zone tables, formal PICS/BIBB/profile/device-advertisement,
`Accepted_Modes`/mode validation, out-of-service tracking/`Reliability`
writability, or intrinsic `CHANGE_OF_LIFE_SAFETY` event-algorithm conformance
(`Event_State` intrinsic-only, `IN_ALARM` latent with no setter).

### Handled Services

The server automatically dispatches:

**Confirmed:**
- ReadProperty, WriteProperty (mutation-gated)
- ReadPropertyMultiple, WritePropertyMultiple (mutation-gated)
- SubscribeCOV, SubscribeCOVProperty, SubscribeCOVPropertyMultiple (mutation-gated)
- CreateObject, DeleteObject (mutation-gated)
- DeviceCommunicationControl
- ReinitializeDevice (decoded and password-validated, then refused with
  `SERVICES / SERVICE_REQUEST_DENIED` for every requested state until an action
  surface exists; no reinitialization or SimpleACK, with password and decode
  errors retaining their existing precedence)
- GetEventInformation, AcknowledgeAlarm
- GetAlarmSummary, GetEnrollmentSummary
- ConfirmedTextMessage
- LifeSafetyOperation (authorized silence/unsilence; reset via configured application executor)
- ConfirmedAuditNotification (explicit sink and fail-closed authorizer; process-local duplicate detection)
- AuditLogQuery (retained records; three-state success filter; no query authorization)
- ReadRange
- AtomicReadFile, AtomicWriteFile (writes are mutation-gated)
- AddListElement, RemoveListElement (mutation-gated)

**Unconfirmed:**
- WhoIs / IAm
- WhoHas / IHave
- TimeSynchronization, UTCTimeSynchronization
- UnconfirmedTextMessage
- UnconfirmedAuditNotification (explicit sink and distinct fail-closed authorizer; no response or duplicate tracking)

**Outgoing (server-initiated):**
- COV notifications (confirmed and unconfirmed, with `NotificationTransactions` retries for confirmed)
- Event notifications (confirmed and unconfirmed, routed via NotificationClass recipients)

Confirmed notification invoke IDs, terminal admission and retries belong to
`NotificationTransactions`. A separate private learned-router cache stores up to
64 DNET next hops from admitted, nonempty routed terminal responses. Routed Address
recipients use a learned router on the first attempt and local broadcast on
later retries; a configured Device binding keeps its fixed next hop. The former
public `ServerTsm` type and its unused transaction methods have been removed
without a compatibility alias. `CovAckResult` remains available at its existing
`bacnet_server::server` path.

### Concurrency

- Lock ordering: always `db` before `cov_table`
- `seg_receivers` capped at 128 (DoS prevention)
- `cov_in_flight` semaphore: max 255 concurrent confirmed COV notifications
- `comm_state`: `Arc<AtomicU8>` — lock-free read

---

## Error Handling

All async operations return `Result<T, bacnet_types::error::Error>`. Key variants:

| Variant | Meaning |
|---------|---------|
| `Error::Protocol { class, code }` | Remote BACnet error response |
| `Error::Timeout(msg)` | APDU retry exhausted |
| `Error::Reject { reason }` | Remote device rejected request |
| `Error::Abort { reason }` | Remote device aborted request |
| `Error::RoutedPathTooLong { dnet }` | Router rejected the active message as too long for DNET |
| `Error::RoutedPathCapacityExceeded { capacity }` | No routed-path entry can be allocated without discarding protected safety state |
| `Error::Encoding(msg)` | Malformed packet |
| `Error::Io(io_error)` | Transport I/O failure |

---

## Transport Configuration Examples

### BIP Client + Server

```rust
use bacnet_client::client::BACnetClient;
use bacnet_server::server::BACnetServer;
use bacnet_transport::bip::BipTransport;
use std::net::Ipv4Addr;

// Client
let client = BACnetClient::bip_builder()
    .interface(Ipv4Addr::UNSPECIFIED)
    .port(0)
    .broadcast_address(Ipv4Addr::BROADCAST)
    .build()
    .await?;

// Server
let server = BACnetServer::bip_builder()
    .database(db)
    .interface(Ipv4Addr::UNSPECIFIED)
    .port(0xBAC0)
    .broadcast_address(Ipv4Addr::BROADCAST)
    .build()
    .await?;
```

### BIP6 (IPv6)

```rust
use bacnet_transport::bip6::Bip6Transport;
use std::net::Ipv6Addr;

let transport = Bip6Transport::new(Ipv6Addr::UNSPECIFIED, 0xBAC0, None);
let client = BACnetClient::generic_builder().transport(transport).build().await?;
```

### BACnet/SC with Hub

#### SC Device UUID migration

`ScServerBuilder::device_uuid([u8; 16])` is now required at runtime: `build()`
returns `Error::Encoding` for omitted/all-zero identity before dialing. Reconnect
configuration is still checked first; the existing TLS/binding/budget checks
retain their relative order. This is an intentional runtime compatibility break
for SC server callers. The Rust SC client already requires a nonzero UUID; its
identity and VMAC policy are unchanged.

The application must generate the UUID before first deployment and durably store
and reuse exactly the same bytes throughout the device's lifetime (base 2020
AB.1.5.3). Pass that stored value each time you build the node; built-in reconnect
reuses it. There is no runtime generation, guessed storage location, persistence
backend, UUID version/variant enforcement, or lifetime-immutability guarantee.
Without application storage/history the library cannot detect a changed UUID.

Distinct devices need distinct UUIDs, independently of their Device instance and
VMAC. Known UUIDs retain the existing intended connection replacement behavior
(AB.6.2.3); two connections sharing one UUID are not expected to coexist. Examples
of **test-only** distinct values are `8e62ac46-d708-4226-9137-76a32b619315` for a
server and `95dfe4ef-97f6-490d-9a2c-f2b4b0c0e682` for a client. Do not deploy these
shared demo identities; supply your own provisioned arrays. The hub also requires
its hosting device's lifetime UUID: see [hub identity migration](#bacnetsc-hub).
Raw `ScTransport` now has the [startup guard](#bacnetsc-client-transport) above;
remote-peer VMAC rules remain unchanged. This does not move
higher-level builder checks or promise that every local VMAC is rejected before
dialing. The owner-approved [#517 acceptance closeout](conformance/standard-135-2020-ledger.md#device-identity-acceptance-closeout)
resolves the scoped default/nil identity problem under these boundaries, not all
low-level public paths or RFC bit-profile/lifetime enforcement; no PICS/profile promotion.

**Receiving hub compatibility break:** a received Connect-Request with an all-zero
Device UUID now fails after TLS/WebSocket establishment and before admission,
activity refresh or replacement. The existing eligible NAK is
`COMMUNICATION/PARAMETER_OUT_OF_RANGE` (7/80), marker zero, not Duplicate-VMAC;
reply addressing uses the envelope source and existing broadcast/reserved-source
suppression. New malformed peers close; malformed repeats retain registration,
negotiated limits and heartbeat/activity state. Legacy raw peers must supply a
nonzero UUID. This local policy treats nonzero bits as opaque, including sparse
or non-RFC-shaped values; generic encoding/decoding and manual raw sending still
permit nil syntax. Initiating nodes silently discard Connect-Accept with a zero
UUID after TLS/WebSocket setup. AB.2 forbids replies to response messages: the
internal range classification is not a wire NAK. Rejection leaves pending state,
peer identity/limits and local identity unchanged and does not restart the
absolute connect wait. A later valid Accept can complete the same handshake;
nil-only traffic times out. Invalid-plus-wrong-ID Accepts are discarded, while
otherwise-valid wrong-ID Accepts retain the terminal mismatch error. Failed
restoration probes do not replace the active failover or reseed the local VMAC.
This receive-shape policy adds no UUID version/variant, generation or storage
requirements; optional [Hub certificate bindings](#hub-certificate-bindings) are
configured separately. See the [scoped evidence](conformance/standard-135-2020-ledger.md#received-peer-uuid-admission).

**Current-dev zero-limit receive policy (Refs #519):** the shared Connect validator
rejects zero Max-BVLC or Max-NPDU in either received Connect message, after the
existing envelope/length/identity checks and before MU diagnostics. This is
**zero-only local policy**, not a universal minimum-capacity conformance claim.
Eligible Requests receive `COMMUNICATION/PARAMETER_OUT_OF_RANGE` (7/80) with the
existing addressing/suppression rules, before activity, admission, capacity or
UUID replacement. Accepts are silently discarded under AB.2: no NAK, pending or
peer-limit commit, Connected publication, or original connect-deadline reset.
Later valid Accepts recover; failed reconnect/restoration probes do not poison
active limits or retire a good failover peer. Local UUID/VMAC are not reseeded.
All positive values remain compatible, including 1/1, 65535/65535, 1200/480 and
300/1476. These are policy boundaries, not proof that tiny capacities can carry
useful services. No positive floor or Max-NPDU/Max-BVLC relationship is imposed.
Local defaults, adapter caps and independent per-peer outgoing budgets remain
unchanged; generic codecs/constructors and manual raw sending still permit zero
syntax. Post-start public mutation is outside this receive guard. #519 remains
open/partial; closed #517 identity acceptance and lifetime exclusions remain valid.
See [zero-capacity evidence](conformance/standard-135-2020-ledger.md#received-zero-capacity-admission).

```rust
use bacnet_client::client::BACnetClient;
use bacnet_transport::sc_hub::{ScHub, ScHubHandshakeTimeouts, ScHubTlsConfig};

// Start the hub with already loaded site CA, hub chain, and matching key DER.
let hub_tls = ScHubTlsConfig::from_der(ca_certs, hub_cert_chain, hub_key)?;
let mut hub = ScHub::start_with_tls_config(
    listen_addr, hub_tls, [0xFF, 0, 0, 0, 0, 1], hub_uuid,
    ScHubHandshakeTimeouts::default(),
).await?;
let hub_addr = hub.local_addr().expect("started hub has a bound address");

// Build the node policy from separately loaded site trust and operational DER.
let tls_config = bacnet_transport::sc_tls::ScNodeTlsConfig::from_der(
    node_ca_certs, node_cert_chain, node_key,
)?;
// Use a persistent nonzero client_uuid, distinct from hub_uuid and every other peer.
let mut client = BACnetClient::sc_builder()
    .hub_url(&format!("wss://127.0.0.1:{}", hub_addr.port()))
    .tls_config(tls_config)
    .vmac([0, 1, 2, 3, 4, 5])
    .device_uuid(client_uuid)
    .build()
    .await?;
// ... use the client ...
client.stop().await?;
hub.stop().await;
```

### MS/TP with USB Adapter

```rust
use bacnet_transport::mstp::MstpTransport;
use bacnet_transport::mstp_serial::{TokioSerialPort, SerialConfig};

let serial = TokioSerialPort::open(&SerialConfig {
    port_name: "/dev/ttyUSB0".into(),
    baud_rate: 76800,
})?;

let client = BACnetClient::generic_builder()
    .transport(MstpTransport::new(serial, 1, 127))
    .build()
    .await?;
```

### MS/TP with Raspberry Pi RS-485 Hat (GPIO)

```rust
use bacnet_transport::mstp::MstpTransport;
use bacnet_transport::mstp_serial::{GpioDirectionPort, TokioSerialPort, SerialConfig};

let serial = TokioSerialPort::open(&SerialConfig {
    port_name: "/dev/ttyS0".into(),
    baud_rate: 76800,
})?;

// Seeed Studio RS-485 Shield: GPIO18 for DE/RE, active-high
let port = GpioDirectionPort::new(serial, "/dev/gpiochip0", 18, true)?;

let client = BACnetClient::generic_builder()
    .transport(MstpTransport::new(port, 1, 127))
    .build()
    .await?;
```

---

### Configured Network Port snapshots

`NetworkPortObject::new_bip(instance, name, BipPortConfig)` constructs a complete,
unbound flat IPV4/NORMAL application configuration. Instance is the declared local
Port ID (local policy: 1–255), separate from UDP port zero. `BipPortConfig` carries
fixed four-octet IP/mask/gateway values, a nonempty DNS array, network number
0–65534, and APDU_Length399 >=50. Defaults are unknown zero addresses/mask/gateway,
one zero DNS address, UDP47808 and declared port capacity1476. Device62 and its
discrete APDU sizes remain independent; neither constructor discovers a NIC or
binds a transport.

The snapshot denies activation-dependent network writes and derives its readonly
MAC from configured IP/UDP. Reconstruct it to change configuration. It has no
pending activation, inert Command, or obsolete port62 projection. Link_Speed is
optional and zero means unknown. The former raw `new` constructor and configuration
setters are removed. `new_non_bip` takes explicit Ethernet/VIRTUAL number, MAC and
capacity and exposes common application rows only; it does not claim a complete
SC or Ethernet profile. Both `DeviceIdentity` database builders use these same
constructors with declared1476 port capacity independent of Device/role limits.
Live transport association, post-bind synchronization and activation are separate.

### Registered B/IP Network Port

This receiving-port association remains a bounded single NORMAL B/IP profile. Local Network Number behavior is described below; complete Network Port conformance, BBMD/foreign-device registration authority and multiport routing remain outside this registration contract.

### Local Network Number controls

The full server and shared endpoint automatically consume the two local nonrouter controls on a NORMAL B/IP, BACnet/SC or MS/TP link. Full B/IP servers and shared endpoints also consume them in BBMD and configured foreign-device modes; full B/IPv6 servers cover normal and configured foreign-device modes. A valid local unicast or broadcast What-Is-Network-Number receives a local-broadcast Network-Number-Is when the owner knows its number (Clauses 6.4.14–6.4.15). There is no proactive startup announcement. An explicit registered Network Port with a nonzero configured number reports `CONFIGURED` and never replaces that number from an announcement. Zero starts `UNKNOWN`; an owner without registration also starts unknown, regardless of other declared objects.

A valid local-broadcast announcement with flag zero updates an unknown/learned owner to `LEARNED`. Flag one sets `LEARNED_CONFIGURED` and takes precedence over all subsequent flag-zero announcements. Further flag-one announcements may replace that learned value, including conflicts; an equal value still upgrades its quality. Both learned qualities transmit flag zero in their own responses. Selected-object `Network_Number` and `Network_Number_Quality` reads use the same database-owned state. Configuration remains immutable, so a new registration resets the pair from configured provenance; a new unregistered runtime starts unknown. There is no persistence of learned state across constructing a new runtime. After stop, the object retains the last observed pair until reconstruction or a new registration.

Routed controls, malformed payloads and unicast Network-Number-Is are ignored. A BBMD Forwarded-NPDU is a logical broadcast even when its UDP hop is unicast and remains eligible. Ignoring number zero, 65535 and flags outside zero/one is this implementation's validation policy, rather than an additional quoted Standard mandate. Conflicting announcements against a locally configured number produce a debug diagnostic without changing configuration.

Standalone clients start UNKNOWN on transports that opt into local nonrouter Number controls. They learn and reply using the same validation and precedence rules, without a Device object, registered Network Port, configured-number setter or persistence. One 256-entry serial worker owns this state; full or closed admission drops only Number controls. A held Number send leaves routed reason-4 Reject correlation and independent APDU dispatch available. Stop aborts and joins both the Number worker and dispatch before transport cleanup, retaining their joins across a canceled stop waiter. Drop aborts both. Already transmitted bytes cannot be retracted. Controlled-client tests qualify the shared intake/lifecycle behavior; Linux NORMAL-B/IP loopback and Ethernet virtual-link tests independently observe actual reply frames. Constrained-TLS SC tests observe Hub broadcast VMAC and exact Number bytes, including replies to direct-peer queries, while ordinary confirmed client requests complete. SC stop/drop retires client connections; the external DirectListener must separately be stopped and joined before its bind is released. Pending-send/queue cancellation remains covered by the generic controlled-client tests, rather than inferred from wire silence. Rust standalone-client B/IPv6 tests independently capture normal selected-link OriginalBroadcast and configured-foreign DBTN with exact source, destination, interface and Number bytes. Positive reply fences cover UNKNOWN, precedence and invalid/admission refusal; stop and eventual Drop release the socket, and reconstruction starts UNKNOWN. These external ignored Linux tests require the integration `ipv6` feature and isolated observer; ordinary hosted CI does not execute them. They add no Python foreign-device API, configured-client authority or physical-LAN claim. Separate isolated Linux standalone-client BBMD/foreign tests capture own Original-Broadcast versus forwarding traffic and exact DBTN to the configured BBMD. Positive Number fences cover UNKNOWN, BDT/FDT admission/refusal, alternate-sender compatibility, precedence and representative invalid/routed controls; registration NAKs retain DBTN attempts and the timer retries registration. An ordinary client ReadProperty completes during live Number controls, and awaited stop permits exclusive socket rebind before client Drop. No configured client number, new registration policy or complete Annex J claim is added. Independent standalone-client MS/TP frame qualification remains under #879.

The pre-1.0 Rust helper moved directly from `bacnet_objects::network_port::NetworkNumber` to `bacnet_types::network_number::NetworkNumber`, with no compatibility alias. Its default is UNKNOWN; `configured(number)` returns `None` for reserved 65535. Pure observation reports configured conflicts to the caller for logging. Shared nonrouter packet parsing and reply encoding live in `bacnet_network::network_number`; registered database authority remains in the server/object adapter.

Transport wrappers must delegate `TransportPort::supports_local_nonrouter_number_controls` when preserving these semantics; the default is false. This capability is independent of NORMAL B/IP registration and conveys no configured-number or control-origin authority.

SC starts UNKNOWN with no configured SC Network Port API; unrelated configured objects provide no authority. SC logical broadcast is the BVLC broadcast destination VMAC. A direct unicast What-Is is valid, but its Number reply uses the Hub broadcast path, never the saved original-direct APDU response capability. Hub-relayed controls do not identify an originating TLS leaf; SC control-origin authorization remains separate (#518). Remaining data links and independent client media/mode qualification remain tracked by #879.

B/IP BBMD and configured foreign modes start UNKNOWN with no registered Network Port authority. BBMD mode learns admitted Original-Broadcast, BDT Forwarded-NPDU and registered foreign-device DBTN announcements; its own Number reply is Original-Broadcast. It rejects an exact self UDP source tuple before forwarded delivery or fanout, preserving the self BDT row and admitted peers on the same IP at different ports. Configured foreign mode accepts structurally valid Forwarded-NPDU from alternate UDP senders under its existing compatibility policy and answers by DBTN to its configured BBMD. Logical broadcast conveys no authenticated origin. Registration rejection does not suppress DBTN attempts; the existing periodic registration loop continues. Shared-endpoint Number wire tests cover BBMD ServerOnly admission and Original-Broadcast replies, foreign ClientOnly alternate forwarding and DBTN through registration rejection/retry, and Both requester/responder progress during live controls plus stop/drop socket release. Linux loopback supplies the independent BBMD broadcast capture; foreign direct capture also runs on macOS. Existing controlled endpoint tests separately prove held-send cancellation and resumed stop. Broader shared-endpoint BBMD/foreign behavior remains experimental; these modes add no configured Network Port authority.

B/IPv6 starts UNKNOWN with no configured IPv6 Network Port authority. Normal mode learns admitted OriginalBroadcast announcements and answers by multicast OriginalBroadcast on the selected link. In the Rust configured foreign-device mode, an admitted Forwarded-NPDU from the configured BBMD is a logical broadcast despite its unicast UDP hop; replies use DBTN to that BBMD. A different BBMD endpoint cannot teach. Unicast NNI, routed controls and malformed payloads remain ineligible. Existing selected-link, source-address, destination/interface and VMAC checks still apply. There is no new IPv6 endpoint builder, number setter or Python foreign-device API.

Linux Ethernet full servers and standalone Rust clients start UNKNOWN with no configured Ethernet Network Port authority. The AF_PACKET receive path admits only the bound MAC and all-FF broadcast, before UI, XID or TEST handling; only all-FF is a logical group. This is the local single-link admission policy, not an additional quoted Clause 7 mandate. Existing self-source refusal remains. Actual isolated Docker Ethernet tests independently inspect destination/source, 802.3 length, LLC bytes, exact learned reply flag zero and padding, and verify stop/drop raw-FD release plus canceled transport-stop resumption. No privileged host interface or physical LAN is involved. The [opt-in fixture](../crates/bacnet-integration-tests/tests/ethernet_network_numbers/README.md) requires Linux and CAP_NET_RAW and is excluded from ordinary CI. There is no Ethernet endpoint builder or Python Ethernet API in this slice.

MS/TP starts UNKNOWN with no configured MS/TP Network Port API. The full server and shared endpoint learn only broadcast DataNotExpectingReply announcements; either a local unicast or broadcast query receives a DataNotExpectingReply to station `0xFF` after token opportunity. Both Tokio and DedicatedThread modes use the existing serial/MAC owner. LoopbackSerial tests independently decode complete standard frames, check precedence and invalid-control recovery with a later valid response as an ordering fence, and qualify application progress while the Number producer is held. Separate post-enqueue and serial-write gates prove canceled stop and drop release that producer without completing a held Number frame. Queue admission alone is not frame transmission; already completed bytes cannot be retracted. This simulator evidence does not qualify physical RS-485 timing, transceiver control or hardware interoperability.

Control work has its own 256-entry receiver and serial worker, so a blocked learning operation or SC Hub write does not stop incoming APDU handling or already-admitted Audit acknowledgment dispatch. A blocked socket writer still serializes physical egress; this does not promise a second concurrent send. Stop seals, aborts and joins that worker before transport cleanup; cancellation retains cleanup ownership. Queued endpoint control sends are caller-owned and canceled with the worker, while a send already started may have reached the wire. The registered-object lease remains with the final socket and admitted work.

The `BACNET-06-NONROUTER-NETWORK-NUMBER` row in the [conformance evidence](conformance/support-summary.md#ledger-rows) covers actual inbound BVLL controls through both B/IP owners, outgoing NPDU observation after a successful real broadcast send, and independent tests of the unchanged BVLL framing layer. The NORMAL B/IP owner fixture does not capture outgoing BVLL frames. Separate full-server BBMD/foreign tests independently decode actual loopback UDP: Linux BBMD tests distinguish own Original-Broadcast replies from Forwarded-NPDU fanout, and cross-platform foreign tests capture DBTN directly. Positive response fences cover refusal and recovery; held producer tests qualify APDU progress, canceled stop, drop and socket release. This loopback evidence does not qualify a physical LAN. Separate constrained-TLS SC fixtures independently decode actual broadcast-VMAC NNI bytes through both owners and `AnyTransport`; deterministic single-writer socket gates qualify bounded control queues, ACK/handler progress, cancellation and joined teardown. Already-admitted detached ordinary APDU sends retain their existing ownership; canceling Number work is not their retraction. Separate opt-in Linux tests capture full-server normal multicast and foreign DBTN bytes with an independent raw observer/BBMD, and a fresh installed Python extension qualifies normal multicast intake/output on the same isolated topology. These external-network tests are distinct from ordinary CI coverage. These controls do not establish a complete Network Port, Annex U/AB or router profile.


A configured object becomes the receiving port only through explicit selection:
`ServerConfig.registered_network_port = Some(oid)`, the server builder's
`.registered_network_port(oid)`, or the B/IP endpoint builder's method of the same
name (`EndpointSession::with_registered_network_port` for direct composition).
The selected built-in IPV4/NORMAL object must already exist with instance 1–255,
matching concrete unicast interface and configured UDP port. Port zero is valid
before bind. BBMD, foreign-device, wildcard-interface and non-B/IP registration
are rejected before publication; declarations alone remain unregistered.
Custom objects and wrappers cannot impersonate a selected built-in: the database
uses crate-authorized concrete storage access before configuration callbacks.
Borrowed Device read views remain supported; no public mutable downcast is exposed.

Startup validates the actual NORMAL capability again after bind and reconciles
only the selected object and optional identity entry with the announced IP, actual
UDP port and derived MAC. Port `APDU_Length` (399) is independently supported at 1476;
Device `Max_APDU_Length_Accepted` (62) may remain 480. Mask, gateway and DNS remain explicit configuration, with
no NIC discovery or fabricated subnet. The obsolete identity `sync_bip_bind`
setter is removed. Configuration/activation writes remain denied, and registered
Out_Of_Service writes, object replacement/removal and adapters are refused before
effects. Protection lasts through admitted work and the final socket/cleanup
owner, including cancellation and Drop; an idle exported role is not a lease.

Full-server RP/RPM and bounded endpoint RP resolve Network-Port instance 4194303
using this owner's selected identity, with concrete ACK object identifiers.
Unregistered responders cannot inherit another owner's association from a shared
database. Mixed RPM succeeds with inline UNKNOWN_OBJECT for an unavailable port
when another property is accessible. Successful target Audit uses the same
concrete object and preserves per-target records. Endpoint responder RPM remains
unsupported. Same-device multiport/router generations, rebind, pending activation,
BBMD/foreign/DHCP and full Network Port conformance remain outside this profile.

`EndpointSession::bip_local_address()` returns the active post-bind announced
address, including the actual ephemeral UDP port, for registered and unregistered
B/IP sessions. It is absent before publication, during/after shutdown and for
other links. This is a logical announced address, not physical NIC provenance.
Cancelled startup can be stopped and joined; transport cleanup failures are
reported by endpoint stop rather than discarded.

## bacnet-endpoint (forward path, RB-18)

`bacnet-endpoint` composes client and server roles for one BACnet device under
one transport owner. One `EndpointSession` owns the transport, ingress, and
shared outbound coordinator. Use its builders when both roles need that shared
lifecycle. Standalone `BACnetClient` and `BACnetServer` remain public APIs with
their own service and data-link capabilities; they are not deprecated. The
endpoint responder's narrower service scope is described below.

### Builders

```rust
use std::net::Ipv4Addr;
use bacnet_endpoint::bip::BipEndpointBuilder;
use bacnet_endpoint::identity::DeviceIdentity;
use bacnet_endpoint::session::SessionRole;

// One device, both roles, B/IP.
let identity = DeviceIdentity::new(1001, 42)?
    .with_bip_port(1, 0, Ipv4Addr::LOCALHOST, 0)?;
let db = identity.build_database()?;
let mut session = BipEndpointBuilder::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST)
    .role(SessionRole::Both)
    .database(db)
    .identity(identity)
    .build_session()?;
session.start().await?;
session.broadcast_i_am().await?;
session.stop().await?;
# Ok::<(), bacnet_types::error::Error>(())
```

`ScEndpointBuilder` composes SC (`build_loopback_session` for unit
validation; `build_hub_session` over a caller-dialed `TlsWebSocket`,
`sc-tls` only, proven against the local constrained-TLS hub).
`MstpEndpointBuilder` composes one serial owner (simulator evidence only —
no bench or on-wire conformance; timing is RB-26).

### Choosing standalone or shared client/server roles

| Standalone construction | Shared endpoint composition |
|---------------------|---------------------|
| `BACnetClient::bip_builder()...build().await` | `BipEndpointBuilder::new(iface, port, bcast).role(ClientOnly).build_session()?` then `start()` |
| `BACnetServer::bip_builder()...build().await` | `BipEndpointBuilder::new(iface, port, bcast).role(ServerOnly).database(db).identity(id).build_session()?` then `start()` |
| Client + server on one device | One `...role(Both).database(db).identity(id).build_session()?` (B/IP, SC, or MS/TP builder) |
| `BACnetClient::sc_builder()...build().await` | `ScEndpointBuilder::new(vmac, uuid)...build_hub_session(ws)?` (dial first, then compose) |
| `BACnetServer::sc_builder()...build().await` | Same `ScEndpointBuilder` with `ServerOnly` + `database` + `identity` |
| `generic_builder().transport(mstp)...` | `MstpEndpointBuilder::new(serial, station)...build_session()?` (one serial owner) |

Notes: the endpoint server role defaults to `ReadProperty` (+ `Reject`/`Abort`
+ segmentation-`Abort`). The explicit Device-write opt-in below adds one
bounded WriteProperty path; full `bacnet-server` parity is out of scope.
The responder supplies exactly RP or RP+WP service bits and exposes neither COV
list property, even for a custom database Device. Server-role identity service
lists must include RP and contain no unsupported bits; validation runs before
ingress even when writes are disabled. WP opt-in accepts RP or RP+WP declarations
and commits RP+WP only after all validation succeeds. ClientOnly creates no
responder and retains its services vector as a local declaration.
Standalone BBMD helpers (`read_bdt` / `write_bdt` / `read_fdt` / foreign
registration) stay on `BipTransport`; the endpoint BBMD setters only stage
pre-start state. Local Number controls have the bounded wire coverage above;
broader BBMD/foreign administration remains experimental.
BIPv6/Ethernet have no endpoint builder — keep the standalone path there and
do not expect identical administration across data links.


### Authorized endpoint Device writes

`EndpointSession::with_device_writes(authorizer)` or
`BipEndpointBuilder::device_writes(authorizer)` enables WriteProperty for the
one local Device's `Description` and, with a complete source profile,
`Audit_Notification_Recipient`. Supply a mandatory Rust
`bacnet_server::mutation::MutationAuthorizer`; its decoded context retains the
immediate peer, claimed routed source, transport provenance and invoke ID.
The callback must be fast, nonblocking and side-effect-free. Refusal or panic
denies before mutation. Provenance is channel scope, not authenticated leaf identity.

Startup requires a server role and exactly one concrete built-in Device in
the attached database. An optional `DeviceIdentity` must match that Device
and contain only ReadProperty/WriteProperty service bits. Configuration
validation precedes transport startup and any profile/source-ownership changes.
The enabled Device and identity advertise exactly RP+WP, including sessions
without an identity. Default sessions keep their existing RP-only responder.
Valid priorities 1–16 are ignored for noncommandable Description. Authorized
NULL relinquishment succeeds without changing its value. Array indices,
out-of-range priorities and other non-string values fail; numeric priority
range errors use SERVICES/PARAMETER_OUT_OF_RANGE. Missing objects/properties
return UNKNOWN_OBJECT/UNKNOWN_PROPERTY; known out-of-scope writes are denied.
Typed Device authority is revalidated under the commit lock, including when
the lower-level responder is used directly. Other targets, properties and
WritePropertyMultiple remain excluded, including source Reporter configuration.

Deterministic request/reply tests cover authorization, framing, routing,
reply channels, group silence, segmentation and shutdown; a B/IP loopback test
covers an authorized write and service-profile readback. Evidence is tracked
in `BACNET-15-ENDPOINT-DEVICE-WRITE` (in progress). This is not general endpoint
mutation parity or inbound replay suppression. The source recipient extension
is described below and in the [Device recipient contract](device-audit-recipient.md).

### Direct endpoint WriteProperty and source WRITE reporting

`ClientRoleHandle::write_property` accepts a direct B/IP IPv4 unicast MAC, a
`bacnet_services::write_property::WritePropertyRequest` (object, property, optional
index, complete encoded property value, optional wire priority), and the required
`bacnet_endpoint::roles::Commandability::{Commandable, Noncommandable}`.
This assertion is required with or without a source Reporter; neither object type,
property identifier, local object state nor the supplied priority establishes it.
The method refuses other endpoint transports and invalid/group destinations before
traffic. There is no routed WP method in this subset.

The shared requester validates zero or more complete TLVs, priority 1–16 when
supplied, and the complete unsegmented APDU size before reserving an Invoke ID.
Empty lists and encoded NULL are distinct valid representations. The wire priority
and bytes remain unchanged. A matching SimpleACK returns `Ok(())`; Error, Reject,
Abort and timeout retain the established error mapping. A wrong-service Error or ACK, or a wrong
ACK shape, cannot complete the write. Error correlation also protects notification
leases in the shared coordinator.

The same session source Audit owner captures live Reporter policy, recipient,
source Device, timestamp, identity and Invoke ID once. Commandable omitted priority
is effective 16 for filtering and reporting, including NULL. Noncommandable writes
ignore priority for Audit, even when it was supplied on the wire. The source
Reporter controls level/operation/priority filtering; remote policy is not consulted.
Eligible attempted writes generate at most one WRITE record across retries, with
complete 0–32-byte `Target_Value` and no value field for larger payloads. The source
never invents remote `Current_Value`, target timestamp, or execution evidence.

Before source admission, cancellation releases caller-owned work. Eligible admitted
writes retain terminal observation after caller cancellation. Nonreported writes
remain caller-owned: cancellation retracts queued requester sends and drops any
in-progress transport future. A transport attempt may already have reached the
peer, so cancellation never proves the write was not executed. Ordinary detached
egress sends retain their existing semantics. The existing 64-operation budget, notification budget,
recipient generation fences, three-second delivery deadline and stop/drop behavior
are shared with reads. Notification failure cannot replace the caller's write result.
Source WP is a bounded extension under #345/#852; WPM, routed writes, standalone
source ownership and other transports remain outside this profile.

### Bounded endpoint source READ reporting

Standalone direct/routed and endpoint ReadProperty share ACK object/property/index
validation (Clause 15.5). Device/Network Port instance 4194303 requests accept only
same-type concrete peer-reported identifiers; other mismatches return decoding
errors. This client contract does not implement the bundled server's Network
Port ingress-port alias mapping (#785).

Endpoint ReadPropertyMultiple accepts 1–64 explicit property occurrences across
nonempty object specifications, with concrete object identifiers. ALL, REQUIRED,
OPTIONAL and wildcard object instances are excluded from this endpoint profile;
standalone RPM retains its broader profile. Array index zero is valid. Shared
RPM request encoding is fallible and validates both lists before appending bytes.

RPM ACK correlation checks all object/property counts, order and identifiers
before returning success or projecting any record. A successful value must echo
the requested index. An inline error may omit a requested index or repeat it,
but cannot substitute another index; an unindexed request requires no index.
The Audit attempt retains the requested index. Indistinguishable duplicate
omitted-index errors cannot reveal a peer's ordering violation. Request and raw
ACK bytes must fit the configured unsegmented max APDU. The server's separate
known-scalar error-index response issue remains tracked in #789.

One RPM operation retains one requester lease, source-operation slot, timestamp,
invoke ID, owned worker and recipient/configuration snapshot across retries and
caller cancellation. Each eligible occurrence produces a separate value-free
READ record, including duplicates. AUDIT_CONFIG excludes Present_Value per
occurrence; returned values remain caller-only. Inline errors retain their
class/code. Whole Error/Abort/Reject, timeout, malformed, mismatched or segmented
outcomes are locally represented by the final operation failure on every eligible
attempted reference; they do not imply remote per-property execution. Notification
admission is independent and bounded through the existing delivery and resource
failure-summary owners; no batch reserves 64 notification permits across request I/O.
Known synchronous egress QueueFull also counts as local resource loss; Closed or
shutdown and already-attempted transport/ACK failures do not. A full-queue summary
returns its count to the same bounded generation-fenced coalescer and waits for
capacity. It never counts itself or retries an ordinary record; stop owns that wait.

After a complete validated RPM ACK, one distinct concrete Device object with at
least one successful property establishes Target_Device for all records in that
operation. Error-only Device results establish none; conflicting successful
Device IDs retain Address attribution without rejecting the otherwise valid ACK.
This is operation-local knowledge, with no discovery cache. Direct B/IP source
limits and the absence of Python source Reporter configuration remain unchanged.

The initiating role supports `read_property`, `read_range`, `read_property_multiple`
and direct B/IP `write_property`, plus explicit
endpoint destinations. ReadRange returns a correlated `ReadRangeAck` with raw
item bytes; empty and multiple-item ACKs each produce one value-free source READ
record. Request encoding validates before output/transaction admission: ALL,
REQUIRED, OPTIONAL, array index zero, zero/non-INTEGER16 counts, and nonconcrete
ByTime components are rejected. Zero position/sequence references are valid and
may match no items. Rust supports all-items, position, sequence and ByTime.
Endpoint requests/responses are unsegmented; a received segmented response is a
failed attempted read and is reported using the caller's terminal result.

On direct B/IP IPv4, provision the typed recipient on the built-in Device and
select `EndpointSession::with_source_audit_reporter`. Device recipient choices
resolve through immutable `BipEndpointBuilder::source_audit_device_binding` entries;
a direct Address choice needs no binding. The local database must have exactly
one concrete built-in Device and the selected Audit Reporter. Configure the Reporter's READ bit
and audit level before startup; both `ClientOnly` and `Both` sessions support
confirmed and unconfirmed notifications. `Both` additionally requires an explicit
Device write authorizer. Startup itself emits nothing.

```rust
use std::net::{Ipv4Addr, SocketAddrV4};
use bacnet_endpoint::{bip::BipEndpointBuilder, DeviceIdentity, SessionRole};
use bacnet_objects::{audit::AuditReporterObject, traits::BACnetObject};
use bacnet_types::{bitstring::AuditOperationFlags, enums::{AuditLevel, AuditOperation, ObjectType}, primitives::ObjectIdentifier};
# async fn example() -> Result<(), bacnet_types::error::Error> {
let mut db = DeviceIdentity::new(123, 42)?.build_database()?;
let local_device = ObjectIdentifier::new(ObjectType::DEVICE, 123)?;
let logger = ObjectIdentifier::new(ObjectType::DEVICE, 999)?;
db.get_mut(&local_device).unwrap().device_authority_internal().unwrap()
    .provision_audit_recipient(bacnet_types::constructed::BACnetRecipient::Device(logger))?;
let mut reporter = AuditReporterObject::new(1, "Source READ")?;
reporter.set_audit_level(AuditLevel::AUDIT_ALL)?;
let mut operations = AuditOperationFlags::empty();
operations.insert(AuditOperation::READ);
reporter.set_auditable_operations(operations);
reporter.set_issue_confirmed_notifications(true);
let source = reporter.object_identifier();
db.add(Box::new(reporter))?;
let mut session = BipEndpointBuilder::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST)
    .role(SessionRole::ClientOnly).database(db)
    .source_audit_device_binding(
        ObjectIdentifier::new(ObjectType::DEVICE, 999)?,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 47808),
    ).build_session()?.with_source_audit_reporter(source);
session.start().await?;
// Use session.client().unwrap().read_property(...) or read_range(...) for a direct IPv4 target.
// Trusted runtime writes use the same Device owner; None relinquishes unchanged.
session.write_audit_recipient(None).await?;
session.stop().await?;
# Ok(())
# }
```

`Monitored_Objects` must be absent for this profile: empty and NULL-only lists
are also rejected, atomically before startup consumes the transport. Selecting
a source requires typed Device provision even at NONE; the removed ownership-only
mode and static recipient selector have no compatibility aliases. Unresolved
Device bindings expose CONFIGURATION_ERROR and suppress ordinary records without
changing READ results or consuming an audit sequence. Source policy and the
Device recipient route are sampled before each admitted READ; a later change
does not rewrite an in-flight request's record or destination. The local
`AUDIT_CONFIG` classification excludes `Present_Value` and includes other
properties. Priority filters do not filter READ. Requests selected for source
reporting reject routed, broadcast, or non-IPv4 destinations before traffic.

A record contains the local source Device, one request-time timestamp, the actual
ReadProperty, ReadRange or ReadPropertyMultiple invoke ID shared across retries, and the requested
property/array index. Successful ReadProperty records use the validated ACK's
object identifier, including concrete Device/Network Port replies to wildcard
requests. On failure or without a valid ACK, the record retains the requested
object (including its wildcard alias) as the attempted identity; it does not
infer a concrete remote object from a malformed or mismatched ACK. A validated
successful concrete Device ACK also establishes Target Device for that record,
for either ReadProperty or ReadRange, as required by Table 19-4.
Network Port and other object ACKs, failures and missing valid ACKs retain the
exact direct BACnet address, including the UDP port. No cross-operation remote
Device cache is created. The selected Device recipient or Address identifies the
logger sink; it is never substituted for the operation target. Unknown user, source
object, remote timestamp, priority and property values are omitted. Independent
source and target reports may both arrive; when the source record retains an
address target, it need not correlate with a target record that knows its own Device.

A valid matching ACK has no Result. Peer Error class/code is preserved when
representable. Local records use Clause 18.7 COMMUNICATION codes for timeout and
known Abort/Reject reasons, including proprietary reasons. Reserved or unmapped
reasons (including Reject reason 10), malformed/mismatching ACKs, and ambiguous
local transport failures use COMMUNICATION/OTHER. These are record fields, never
Error PDUs sent to the peer. An already-observed peer terminal takes precedence
over a contradictory local send error. Rejected pre-send admission is silent;
a later retry failure retains evidence of earlier transmission attempts.

Once an audited request transfers to session ownership, dropping its caller
waiter does not cancel it: the session observes the response or deadline and
records once. Ordinary requests retain caller-owned RAII cancellation. There
are 64 whole-operation slots, acquired before asynchronous policy reads, and a
separate shared pool of 64 active audit notifications. Read results do
not wait for audit delivery. Notifications have one absolute three-second
send/ACK deadline, no retries and no ordinary-record backlog. Expired or canceled
queued notification commands are discarded before transport execution; a send
already in progress may have reached the peer when cancellation wins.

Overload, encoding, send and acknowledgment failures update the selected
Reporter's instance-owned Reliability without replacing the read result.
Completion authority includes the configuration generation: an old delivery
cannot clear a newer failure or update health after configuration changes.

Eligible, encodable READ records that fit the APDU but lose admission to the
shared audit permit pool or confirmed invoke-ID pool contribute to one bounded,
memory-only AUDITING_FAILURE batch. The local filtering policy requires a
non-NONE Audit_Level and the AUDITING_FAILURE operation bit. The summary places
the earliest lost record's source timestamp in Target_Timestamp, the local
Device in both Source_Device and Target_Device, and a saturating application
Unsigned count in Current_Value. Other optional fields are absent. Earliest
means record admission order, including reversed completions, sequence wrap and
changes of clock representation. Encoding/size errors, filtering, pre-send
rejection, closed admission, transport/ACK failures and summary failures do not
contribute. Failed summaries never recursively produce another summary.

One owned worker waits passively for actual semaphore or shared coordinator
capacity; requester-only releases also wake it. Further losses coalesce into
sequential batches, without queuing or replaying ordinary records. Each batch
belongs to one immutable Reporter instance, configuration generation, delivery
mode and destination. Changes discard incompatible pending counts, including
A-to-B-to-A changes without another READ. Active Device/Reporter removal and
replacement are denied. A new context
can supersede the single pending slot; stale completions cannot transfer their
counts into it. Target reporting instead retains bounded captured historical
contexts, as described in [delayed target Audit reporting](delayed-target-audit.md). Admitted notifications retain the three-second total deadline and
no retries.

`stop()` seals admission, cancels operations and notifications, and joins owned
workers before uninstalling under the DB guard. Canceled stop retains sealed
protection and join handles for a later stop; Drop cancels and retains structural
protection only until owned task frames quiesce. Source projection and configuration
restrictions deactivate on sealing. Shutdown and context changes can lose
undelivered records and pending counts. This is not a durable delivery promise
or full Audit Reporting/BIBB/BTL conformance. Other source operations, multiple Reporters,
selector semantics, batching/send delay, standalone source ownership and other
transports remain outside this subset.


### Object-owned AV/BV Audit policy

Analog Value and Binary Value support independently optional, writable
`Audit_Level`, `Auditable_Operations`, and `Audit_Priority_Filter` properties.
Provision `bacnet_objects::audit::ObjectAuditPolicy` through `set_audit_policy`
before registration. `None` omits a property; DEFAULT level and
`AuditPriorityPolicy::Inherit` (a present NULL priority filter) inherit the selected
Reporter's settings. Metadata and Property_List expose only provisioned rows.
Only commandable AV/BV instances expose the optional Audit_Priority_Filter;
it applies to commandable-property writes, not Description or lifecycle
operations. Noncommandable instances retain the other supported provisioned
Audit fields. Provisioning does not install or enable a Reporter.

Target READ/WRITE/CREATE/DELETE use the effective instance policy. The selected
Reporter's NONE level remains the master suppression boundary. With an enabled
Reporter, an actual object Audit_Level change is recorded across NONE and despite
a cleared WRITE bit. Actual Auditable_Operations changes bypass WRITE only while
the effective object level is enabled. Equal-value and failed writes use ordinary
filters. Each WPM element captures its pre-state; later elements see committed
policy. Successful BV CREATE uses the created policy, DELETE captures it before
removal, and failed CREATE uses Reporter fallback. Network AV creation remains
unsupported. Source reporting ignores remote object policy.

For those eligible actual setting changes, network WP, each WPM element and
`BACnetServer::write_local` prepare the immediate notification before assigning
the built-in policy field. Unavailable route, runtime, send capacity, confirmed
lease or APDU fit returns SERVICES/SERVICE_REQUEST_DENIED without changing that
field, consuming a clockless sequence or retaining a worker/lease. WPM keeps its
successful prefix and stops at the denied element. This stronger admission rule
is a local policy, not a Standard-mandated write rejection. A successful admission
owns one bounded delivery attempt; later send/ACK failure cannot undo the write.
Ordinary, equal and NULL writes keep their existing best-effort behavior. These
mandatory records bypass the separately configured [delayed target queue](delayed-target-audit.md).

`BACnetServer::write_local` uses the same target observer, with local Device
provenance and no invoke ID. Device recipient changes still emit only their
old/new pair. Application Input/noncommandable Value updates through `set_present_value_local`
are silent to the target Audit observer;
raw object/database authoring bypasses notification ownership.

The AV/BV object clauses (§12.4 printed185/PDF187; §12.8 printed211/PDF213)
inherit the Reporter's priority filter when the object row is absent or NULL.
Generic §19.6.3 (printed820/PDF822) conflicts for the absent case. This bounded
implementation follows the object-specific clauses; the 2024-04-29 errata does
not resolve that wording and adds the commandability condition. Other object
families and broader Audit completion remain open.

### Target Device Audit recipient

The standalone target profile uses `DeviceObject::provision_audit_recipient` for
initial state and `AuditReportersConfig { reporters }` for selection. Active local
and authorized network recipient writes share atomic old/new delivery admission.
See the [Device recipient contract](device-audit-recipient.md) for supported routes,
metadata, failure semantics and shutdown ownership. The endpoint source profile
uses the same typed Device value and a source-owned paired delivery path; it has
the narrower role, route and service boundaries described above.

### Multi-device batch concurrency

`BACnetClient::{read_property_from_devices, read_property_multiple_from_devices,
write_property_to_devices}` take `Option<std::num::NonZeroUsize>` for their
concurrency limit. `None` uses 32; `Some(NonZeroUsize::new(1).unwrap())` serializes
the requests. Zero is unrepresentable at this boundary. All three retain their
`Vec` results in completion order and complete empty batches. Each
`DeviceReadResult`, `DeviceRpmResult` and `DeviceWriteResult` now includes
`request_index: usize`, the zero-based occurrence in the original input vector,
including duplicate identical requests to one Device. The existing `device_instance`
and typed `Result` outcomes remain; requests are consumed without cloning a full
request or encoded write value into the result. Use the index to correlate with
caller-owned input metadata. This is a pre-1.0 result-shape change without aliases.

Dropping the batch future cancels pending requests and stops queued work without
returning a partial vector; already-sent remote writes cannot be retracted.
`DeviceWriteRequest` Debug shows the encoded value length instead of its bytes;
RP/RPM result Debug omits successful ACK payloads. Values remain accessible through
the public outcomes, and other error/debug formatting is not a secrecy boundary.
