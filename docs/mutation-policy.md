# Local mutation authorization

Rust operators can set `ServerConfig::mutation_policy` or call
`.mutation_policy(bacnet_server::mutation::MutationPolicy::DenyAll)` on the generic,
B/IP or SC server builder. The native default is `Permissive`:
an absent authorizer allows; an installed authorizer must approve. `DenyAll` denies
covered decisions even with an allow-all authorizer, without invoking it, using
SERVICES / SERVICE_REQUEST_DENIED. Both modes accept any authorizer configuration.

**Inbound WriteGroup is decided per Channel write (#1319).** A WriteGroup can
write several Channels, so policy judges each Channel write on its own, just before
it is made: `DenyAll` denies it, and an installed authorizer can allow some Channels
and not others. A denied write is skipped silently, since nothing answers an
unconfirmed request, makes no Audit record, and is counted in the `write_group` row of
`mutation_decision_counters()`.

**Check an existing authorizer for WriteGroup.** Before #1319 an installed authorizer
never saw a WriteGroup, which was dropped whatever it returned. A callback that allows
what it doesn't recognize, through `matches!`, `if let` or a `_ => true` arm, now
allows WriteGroup Channel writes. `MutationTarget` isn't `#[non_exhaustive]`, but
such callbacks still compile, so handle `MutationTarget::WriteGroup` explicitly.

**SC mTLS channel/peer authentication is not service authorization.** Identities at
this layer are claimed link/routed addresses, never certificate principals.
Distinguishing SC certificate principals is out of scope: none reaches this layer.

## Authorization context

Each decision receives a `mutation::MutationAuthorizationContext`:

- `source_mac` / `source_network` — claimed immediate peer and routed origin.
  Never authenticated identities, never certificate principals.
- `provenance` — the reassembled ingress snapshot (`TransportProvenance`)
  threaded from dispatch through `handle_admitted_confirmed_request[_with_lso]`
  into `mutations::Request`. Cross-segment provenance mismatches already fail
  closed at reassembly, so every element of one request (including each WPM
  element) observes the same snapshot.
- `trust` — `mutation::MutationTrust` derived from the snapshot, mirroring
  RB-09 `ControlTrust`: `Unverified`, `VerifiedChannel` (direct SC-TLS peer),
  or `VerifiedRelay` (SC-hub relayed origin). Channel/relay scope only, never
  leaf identity: a verified scope asserts the channel/relay validation, not
  that a claimed SNET/SADR leaf is the authenticated peer.
- `direct_sc_identity()` — the sealed accepted-direct TLS leaf-DER SHA-256 and
  process-lifetime connection incarnation, when present. Same-leaf reconnects
  get new incarnations; queued complete work retains its original snapshot
  after replacement. Hub-relayed and unverified ingress have no direct identity.
- `invoke_id`, `service_choice`, `target` — the request's identity and the
  decoded mutation (current element for WPM). `service_choice` is a
  `mutation::MutationService`: `Confirmed(choice)` with `Some` invoke ID for the ten
  confirmed services, `Unconfirmed(WRITE_GROUP)` with no invoke ID for a WriteGroup,
  whose `target` is `MutationTarget::WriteGroup` naming the Channel, the group, the
  channel number, the priority used, the encoded value and the inhibit flag.

`Debug` for the context is redacted by construction: address lengths, the
provenance/trust labels, and the target kind only — never MAC bytes, property
values, file payloads, or other decoded inputs.

## Baseline-only profile

Direct TLS identity is separate from claimed addresses and authorization.
Hub-relayed end-to-end identity and response confinement (#524) remain separate:

- An unknown origin — including a hub-mediated unknown leaf, which arrives
  `Unverified` — never satisfies a baseline-only allow rule. The gate delivers
  the snapshot; the operator's callback owns the rule.
- Receive-permission is not write-permission: allowing one covered service
  (for example a COV subscription) never implies allowing another (for
  example a property write). Each covered decision needs its own allow.
- The SC VMAC is payload-claimed inside the TLS channel, not bound to the
  operational certificate. The direct leaf fingerprint does not establish a
  certificate-to-VMAC/UUID/SNET/SADR mapping. See the
  [identity API and limits](rust-api.md#accepted-direct-tls-identity).

## Timing and side effects

Order per request is validation, then authorization, then mutation, with no
audit-log write on deny: a denial performs no database mutation, no COV/event
fan-out, and no audit-log write (that write would itself be a mutation). It is
recorded in the saturating per-service decision counters and bounded tracing
diagnostics only. The callback runs after DCC prechecks, request admission,
service decoding, and per-element validation, and before the database write;
WPM invokes it per validated element in wire order while holding the database
write lock, so callbacks must stay fast, nonblocking, reentry-free, and
side-effect-free, and may run concurrently. A panicking callback denies
fail-closed. Neither the allow nor the deny path generates an audit record for
the decision itself; audit records arrive only as explicitly authorized
AuditNotification service receptions.

**WPM elements an object saves first are decided ahead (#1321).** A Notification
Forwarder's or Notification Class's list, an Access Rights object's rule arrays,
Enable or Accompaniment, and an Audit Log's Log_Enable or Buffer_Size are saved
before the object serves them, and the server stages that save so it runs with the
database write lock released. For such an element the callback is asked before the
save is staged, under a database read guard, after the element's own validation and
in wire order among such elements, so ahead of earlier elements no object saves
first; only allowed elements are staged, up to one whose value doesn't decode, and
the handler applies the recorded decision when it reaches the element instead of
asking again. The callback is still asked once per element, but it can be asked
about an element the request never reaches, when an earlier element fails for
another reason. A request with no such element asks nothing ahead. The decision
counters and audit records cover only the elements the handler reaches, as before.

Coverage is the ten confirmed `mutation::MutationTarget` services and the Channel
writes of an inbound WriteGroup, each decided after the change list is decoded and
matched to the Channels, with no database guard held. Reads, discovery, DCC,
TimeSync, LifeSafety/Audit, direct handler calls and trusted local writes retain
their existing behavior. Admission, duplicate detection, decoding and WPM validation
retain precedence. WPM makes one decision per reached element; empty requests make
none, and a denial stops the suffix without rolling back an allowed prefix.
WPM denials keep the `first_failed` error shape; other denials use
SERVICES / SERVICE_REQUEST_DENIED.

## Exclusions

- Direct `pub handle_*` calls and trusted local writes (`write_local`,
  `set_present_value_local`, life-safety arming) stay ungated by design — the
  same documented bypass contract as the RB-09 precedent. No raw
  server-receive path skips `mutations::Request`.
- The shared endpoint has a separate narrow [Device-write authorizer](rust-api.md#authorized-endpoint-device-writes);
  this standalone policy does not configure it.
- LifeSafetyOperation, DeviceCommunicationControl, ReinitializeDevice and Audit
  keep their separate policy and configuration paths.

## Python configuration

`BACnetServer(..., mutation_policy="permissive")` selects the same native default.
Set the keyword-only option to `"deny_all"` to deny valid inbound WriteProperty,
WritePropertyMultiple, CreateObject, DeleteObject, AddListElement,
RemoveListElement, AtomicWriteFile, SubscribeCOV, SubscribeCOVProperty and
SubscribeCOVPropertyMultiple decisions through the existing Rust gate. Denials
use SERVICES / SERVICE_REQUEST_DENIED (with WPM's existing failed-reference shape).
No Python callback or separate authorization gate is installed.

Other strings raise `ValueError`, and non-strings raise `TypeError` synchronously
in the constructor, before startup drains registrations or performs transport
I/O. Reads and trusted local `write_property_local` calls remain available under
`"deny_all"`. It also denies each Channel write of an inbound WriteGroup to a Channel
added with `add_channel`. The option does not configure DCC, ReinitializeDevice, LifeSafety,
Audit or endpoint authorization, and does not establish a certificate principal.


`BACnetServer::mutation_decision_counters()` exposes fixed per-service saturating
`u64` totals, including after `stop()`: `allow_total`, `deny_total` (all denials),
and `policy_deny_total` (the deny-all subset). Samples are independent, not atomic
aggregates. They count decisions, not successful mutations or delivered responses;
they never affect authorization and retain no per-source state or durable history.
Each Channel write of an inbound WriteGroup counts once in the `write_group` row.
