# BACnet Standard 135-2020 Conformance Ledger

> DRAFT internal support evidence. This ledger is not a BTL certification claim, a formal PICS, or a formal BIBB declaration.

## Scope

- Standard: ANSI/ASHRAE Standard 135-2020.
- Reviewed at: 2026-06-29.
- Implementation evidence SHA reviewed: `7683d12b4ed4adbf22fbf7baf3fbf38b8767c81b`.
- Machine-readable source: `conformance/bacnet-135-2020.json`.
- Current scope: Annex AB.6.2.3 BACnet/SC accepting-peer duplicate Device UUID replacement at the hub.
- Addenda/errata status: Local source `_spec/2020_ASHRAE_Standard-135-BACnet-Data-Communication-Protocol.pdf` was reviewed for Annex AB.6.2.2 and AB.6.2.3 duplicate Device UUID replacement, VMAC-collision NAK behavior, and initiating-peer Random-48 reselection context. The ASHRAE Standards Addenda and Errata pages were checked on 2026-06-29 for Standard 135-2020 addenda/errata through addenda bv, bx, ca, cc, cd, ce, cf, ch, ci, cj, ck, cn, cm, co, cp, cq, and cs, plus the 135-2020 base errata summary and listed addendum errata. The listed 135-2020 addenda/errata text was searched for AB.6.2, Device UUID, NODE_DUPLICATE_VMAC, VMAC collision, Random-48, Connect-Request, and Connect-Accept. Base 135-2020 errata corrects an AB.6.2.3 Disconnect-ACK peer-label typo; Addendum cc references AB.6.2.2/AB.6.2.3 for Network Port/hub-connection metadata; Addendum cp adds the Hello destination option to Connect-Request/Connect-Accept. None changes the AB.6.2.3 duplicate Device UUID or VMAC-collision transitions covered by this tranche.

## Status Taxonomy

| Status | Meaning |
|---|---|
| `in-progress` | Ledger/support artifact exists but is not complete evidence. |
| `implementation-present-needs-conformance-tests` | Source anchors exist; clause-specific positive tests are incomplete. |
| `implementation-present-needs-negative-tests` | Source anchors exist; malformed/unsupported-path tests are incomplete. |
| `implementation-present-needs-security-tests` | Source anchors exist; security/TLS/auth/fail-closed tests are incomplete. |
| `implementation-present-needs-timeout-tests` | Source anchors exist; deterministic timeout tests are incomplete. |
| `implementation-present-needs-state-machine-audit` | Source anchors exist; state transition audit/tests are incomplete. |
| `implementation-present-needs-window-tests` | Source anchors exist; segmentation/window tests are incomplete. |
| `implementation-present-needs-source-review` | Source appears present; detailed clause review is still needed. |
| `implementation-present-needs-platform-tests` | Source appears present; platform or hardware-adjacent evidence is needed. |
| `supported-with-clause-evidence` | Positive tests, anchors, and public claims support this row. |
| `deferred-pending-owner-decision` | Support direction requires an explicit owner decision. |
| `unsupported-by-design` | Intentionally unsupported with documented rationale. |
| `unknown-pending-source-review` | No reviewed implementation evidence yet. |

## Clause 4 Architecture

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-4-ARCHITECTURE` | Clause 4 | P2 | `implementation-present-needs-source-review` | Workspace crates and `docs/architecture.md` establish the current architecture map. |

## Clause 5 Application Layer

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-5-TSM-CLIENT` | Clause 5.4.4 | P1 | `implementation-present-needs-state-machine-audit` | Client TSM paths exist under `crates/bacnet-client/src/client`. |
| `BACNET-5-TSM-SERVER` | Clause 5.4.5 | P1 | `implementation-present-needs-state-machine-audit` | Server segmentation and handler paths exist under `crates/bacnet-server/src`. |
| `BACNET-5-SEGMENTATION-WINDOW` | Clauses 5.2-5.4 | P1 | `implementation-present-needs-window-tests` | Segmentation code and integration tests exist; window edge cases remain open. |

## Clause 6 Network Layer

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-6-NPDU-CONTROL` | Clause 6.2 | P1 | `implementation-present-needs-negative-tests` | NPDU codec and network layer paths exist. |
| `BACNET-6-ROUTER-MESSAGES` | Clauses 6.4-6.6 | P1 | `implementation-present-needs-conformance-tests` | Router code and stress benchmark paths exist. |

## Clauses 7-11 Data Links

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-7-ETHERNET-LLC` | Clause 7 | P2 | `implementation-present-needs-platform-tests` | Ethernet transport claim exists; platform tests remain open. |
| `BACNET-8-ARCNET` | Clause 8 | P3 | `unknown-pending-source-review` | No public support claim found in the initial scan. |
| `BACNET-9-MSTP-FRAMES` | Clause 9.3 | P2 | `implementation-present-needs-source-review` | MS/TP frame and transport paths exist. |
| `BACNET-10-PTP` | Clause 10 | P3 | `unknown-pending-source-review` | No public support claim found in the initial scan. |
| `BACNET-11-LONTALK` | Clause 11 | P3 | `unknown-pending-source-review` | No public support claim found in the initial scan. |

## Clauses 12-19 Objects, Services, And Procedures

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-12-OBJECT-MODEL` | Clauses 12-19 | P1 | `implementation-present-needs-conformance-tests` | Object model, server handlers, and existing PICS generator paths exist. |

## Clauses 20-21 Encoding And Formal APDUs

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-20-ENCODING` | Clause 20 | P1 | `implementation-present-needs-negative-tests` | Encoding modules and tests exist. |
| `BACNET-21-FORMAL-APDUS` | Clause 21 | P1 | `implementation-present-needs-conformance-tests` | APDU and service modules exist. |

## Annex A PICS

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-A-PICS` | Annex A | P1 | `in-progress` | `bacnet-server::pics` exists; generated draft summary is not a certification claim. |

## Annex J BACnet/IP

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-J-BVLC-FUNCTION-CODES` | Annex J.2 | P0 | `implementation-present-needs-conformance-tests` | J-01 covers Annex J.2 constants through `0x0B`, representative frames, malformed type/length, unknown function passthrough, deleted-value passthrough, and current decoder policy for extra bytes beyond BVLC Length. J-02 adds exact two-byte BVLC-Result parsing, unknown result-code passthrough, malformed result rejection, and sender/expected-function correlation for pending management responses. J-13 adds reproducible local and base/head benchmark runners for BIP Criterion suites with ignored raw artifacts and a machine-readable result-row schema. |
| `BACNET-J-ORIGINAL-UNICAST-NPDU` | Annex J | P0 | `implementation-present-needs-negative-tests` | J-04 Original-NPDU evidence covers UDP sender B/IP MAC delivery and self-originated frame suppression; directed reply-path integration remains open. |
| `BACNET-J-ORIGINAL-BROADCAST-NPDU` | Annex J | P0 | `implementation-present-needs-negative-tests` | J-04 Original-NPDU evidence covers BBMD Original-Broadcast local delivery, BDT/FDT Forwarded-NPDU fanout with original sender preservation, and no local Forwarded-NPDU echo. J-09 adds platform socket evidence for INADDR_ANY broadcast reception and SO_BROADCAST Original-Broadcast-NPDU sends. J-10 adds B/IP send-path evidence that Clause 6 global-broadcast and remote-broadcast NPDUs preserve DNET, DLEN 0 broadcast DADR, Hop Count, and APDU bytes unchanged inside Annex J Original-Broadcast-NPDU. Additional malformed/unsupported-path coverage remains open. |
| `BACNET-J-FORWARDED-NPDU` | Annex J | P0 | `implementation-present-needs-negative-tests` | J-04 covers originating-address parsing, truncated-address rejection, BBMD delivery with originating B/IP source MAC, FDT fanout preserving the origin, local rebroadcast for unicast peer arrivals, directed-broadcast peer local-rebroadcast suppression, no onward forwarding to other BDT peers, and Original-Broadcast BDT/FDT Forwarded-NPDU emission. Non-BDT Forwarded-NPDU evidence verifies rejection before local delivery, local rebroadcast, BDT fanout, or FDT fanout. DBTN evidence covers registered foreign-device fanout to local broadcast, BDT peer, and non-origin FDT peer while preserving the origin, excluding origin echo, checking for no extra duplicate frames, and returning `X'0060'` when deterministic local Forwarded-NPDU forwarding fails. |
| `BACNET-J-BBMD-BDT` | Annex J.4/J.5 | P0 | `implementation-present-needs-conformance-tests` | J-03 covers read/write BDT caller paths, replacement semantics, malformed Write-BDT NAK without table mutation, self-entry insertion without overflow, and directed-broadcast forwarding target calculation. J-04 adds Forwarded-NPDU BDT mask behavior, no onward forwarding to other BDT peers, non-BDT sender rejection before BDT fanout, and Original-Broadcast one-peer fanout without local echo. DBTN fanout covers a registered foreign-device request forwarded to a BDT peer plus local broadcast and FDT targets without extra duplicate frames. J-07 adds project ACL evidence for the legacy Write-BDT path: listed management senders can update the table, and unlisted senders receive the standard Write-BDT NAK without table mutation. J-08 adds BDT persistence evidence: successful Write-BDT stores the current wire-format BDT for restart load, and invalid persisted bytes fall back to the configured BDT without accepting malformed state. J-11 adds Read-BDT-Ack payload validation evidence for Annex J.2.4 `N*10` BDT entry sizing. J-12 adds raw BBMD Read-BDT-Ack wire evidence for ACK function code and `N*10` BDT entry bytes. J-13 adds reproducible BBMD stress benchmark A/B runner evidence with ignored raw artifacts and a machine-readable result-row schema. |
| `BACNET-J-FOREIGN-DEVICE-FDT` | Annex J.5 | P0 | `implementation-present-needs-conformance-tests` | J-03 covers FDT read/register/delete caller paths, re-registration, zero-TTL and malformed TTL NAKs, exact Delete-FDT payload length, max TTL remaining-time capping, expiry purge, source exclusion, and unregistered DBTN NAK without local delivery. J-04 Original-Broadcast evidence covers one registered FDT target; DBTN evidence covers registered origin plus peer FDT fanout, source preservation, no echo to the originating foreign device, no extra duplicate FDT frames, and `X'0060'` when forwarding cannot be completed. Non-BDT Forwarded-NPDU evidence verifies no FDT fanout. J-06 adds a BBMD-owned timer purge task for Annex J.5.2.3, covers expiration without an inbound BVLC request, and covers re-registration resetting the entry before the purge task removes it. J-07 adds project ACL evidence for Delete-FDT: listed management senders can delete registered entries, and unlisted senders receive the standard Delete-FDT NAK without removing the entry. J-11 adds Read-FDT-Ack payload validation evidence for Annex J.2.8 `N*10` FDT entry sizing. J-12 adds raw BBMD Read-FDT-Ack wire evidence for ACK function code and `N*10` FDT entry fields. J-13 adds reproducible foreign-device/BBMD stress benchmark A/B runner evidence with ignored raw artifacts and a machine-readable result-row schema. |
| `BACNET-J-NAT-TRAVERSAL` | Annex J.7.5 | P0 | `deferred-pending-owner-decision` | Current IPv4 B/IP surfaces expose interface, port, broadcast address, BDT/FDT management, and foreign-device registration, but no reviewed global B/IP address field, NAT mode flag, BBMD/router logical-port model, or NAT-specific originating-address rewrite. Follow-up work item `019f0ff8-14c0-7013-9721-3bc5fe0356de` tracks the owner decision and implementation plan if support is later claimed. |
| `BACNET-J-IP-MULTICAST` | Annex J.8 | P0 | `deferred-pending-owner-decision` | Current IPv4 B/IP transport sends local broadcasts to a configured IPv4 broadcast address and has no B/IP-M multicast group membership, multicast send, or B/IP-M BBMD group configuration. BACnet/IPv6 multicast evidence belongs to Annex U, not Annex J. Follow-up work item `019f0ff8-14e7-7681-8738-032683da62df` tracks the owner decision and implementation plan if support is later claimed. |

## Annex K BIBBs

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-K-BIBBS` | Annex K | P1 | `in-progress` | Generated draft is a starting point only; detailed service mapping remains open. |

## Annex L Profiles

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-L-PROFILES` | Annex L | P2 | `in-progress` | Profile evidence must be derived from ledger/PICS rows later. |

## Annex U BACnet/IPv6

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-U-IPV6-BVLL` | Annex U | P2 | `implementation-present-needs-conformance-tests` | B/IP6 codec and benchmark paths exist. |

## Annex AB BACnet/SC

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-AB-SC-FRAME` | Annex AB.2 | P0 | `implementation-present-needs-negative-tests` | AB-01 adds transport and WASM codec evidence for reserved control bit rejection, Header Option Type `1..31` enforcement, AB.2.17 destination/data option marker decoding, VMAC field ordering, option count cap enforcement, option length/data truncation rejection, and unterminated option-chain rejection. Addenda 135-2020cf/cp were checked: cf renames Data Options bit 6 to Every Segment without changing the marker bit position, and cp adds standard header option types 2..5 accepted by the generic `1..31` parser. Non-Result function-specific payload semantics, destination-option Must Understand NAK behavior, Every Segment segmentation behavior, and hub/direct-connection behavior remain open. |
| `BACNET-AB-SC-BVLC-RESULT` | Annex AB.2.4 | P0 | `implementation-present-needs-conformance-tests` | AB-02 adds typed BVLC-Result ACK/NAK payload parsing for transport and WASM. ACK fixtures use the Proprietary-Message function per addendum 135-2020ci; NAK fixtures mirror AB.2.17 examples with and without UTF-8 Error Details, including the Figure AB-6 multibyte UTF-8 details bytes. Connection handling keeps ACK benign, disconnects on NAK, closes on handshake/receive-loop fatal Results, and disconnects on malformed Result without generating a Result response. Negotiated Max-BVLC-Length resource-limit evidence is tracked under `BACNET-AB-SC-CONNECTION-STATE`. Request correlation, Error Details resource limits, standard-function ACK diagnostics, and full AB.3.1.5 Result generation remain open. |
| `BACNET-AB-SC-CONNECTION-STATE` | Annex AB.6.2 | P0 | `implementation-present-needs-state-machine-audit` | AB-03 adds native and WASM Connect-Accept message-id matching evidence, keeps pure state-machine mismatches in Connecting, and makes the async native handshake fail/disconnect on a mismatched response. Native and WASM peers now require the fixed AB.2.11.1 26-byte Connect-Accept payload, store peer Max-BVLC-Length/Max-NPDU-Length, advertise local Max-BVLC-Length, reject outbound messages above peer limits, and discard oversized inbound WebSocket payloads before BVLC processing. The hub stores client Max-BVLC-Length/Max-NPDU-Length, advertises hub limits, rejects non-26-byte Connect-Requests, drops inbound frames above hub limits, and filters relay targets by each recipient's negotiated limits. AB-07 stores each hub client's Device UUID, accepts known-UUID Connect-Request replacements, sends a WebSocket Close to the superseded connection, wakes the superseded handler, keeps superseded sinks from relaying or removing the replacement entry, and revalidates both source and recipient closed tokens immediately before relay writes so marked-superseded sinks are not written after replacement wins. It also preserves NODE_DUPLICATE_VMAC NAK behavior for a new UUID that collides with an existing client or hub VMAC. Live generated-certificate WebSocket evidence requires the superseded connection to receive a Close frame, rejects a second Connect-Request from an already connected client without replacing the claimed peer, verifies the closed client's original VMAC is no longer reachable, verifies peer reachability after that invalid connected-state transition, and decodes duplicate-VMAC BVLC-Result NAK values at the WebSocket boundary. Remaining gaps include adapter-boundary AWAITING_WEBSOCKET evidence, accepting-peer connect-wait timeout, Disconnect wait in `ScTransport::stop`, reserved VMAC error signaling, and initiating-peer Random-48 VMAC reselection after NODE_DUPLICATE_VMAC. |
| `BACNET-AB-SC-HUB-CONNECTOR` | Annex AB.5 | P0 | `implementation-present-needs-conformance-tests` | AB-06 adds hub connector/forwarding evidence: hub-bound Encapsulated-NPDU uses Destination VMAC present and Originating VMAC absent; local receive drops hub-relayed non-broadcast Destination VMAC; hub rejects Originating-VMAC-present or missing-Destination forwarding attempts; unicast selects only the matching VMAC and unknown unicast has no recipient; broadcast targets all current hub connections except origin; relay preserves Message ID/payload/destination options/data options, adds sender Originating VMAC, strips Destination VMAC for unicast, and preserves broadcast Destination VMAC. Live three-client WebSocket evidence covers A-to-B unicast, A-to-unknown discard, and A broadcast to B/C but not A. AB-07 adds live WebSocket evidence that known Device UUID replacement moves hub reachability to the replacement VMAC, prevents old-VMAC unicast delivery, requires a Close frame for the superseded connection, prevents marked-superseded source or recipient sinks from relaying after replacement wins, and preserves peer reachability after rejecting a connected client's second Connect-Request. Transport connector evidence covers primary timeout/failover, established primary loss with reconnect exhaustion, active send-path swap to failover, and primary restoration while failover is active. Larger option-chain evidence covers 31 minimum-size Destination Options plus 31 minimum-size Data Options within the 1476-byte BVLC budget, preserved through the relay helper and live WebSocket unicast path, with helper broadcast preservation. Addendum cc affects AB.5.3.1 metadata, not these forwarding, replacement, reconnect-failover, or option-preservation transformations. Remaining gaps: configured/malformed URI coverage and direct-connection classification/NAK behavior. |
| `BACNET-AB-SC-WEBSOCKET-TLS` | Annex AB.7 | P0 | `implementation-present-needs-security-tests` | AB-04 adds native and WASM evidence for rejecting non-`wss` peer URIs before dialing, requesting and verifying the `hub.bsc.bacnet.org` subprotocol, rejecting missing/wrong hub subprotocol offers, and closing non-binary WebSocket data frames with status `1003` at the real TLS WebSocket hub boundary. Binary BVLC-SC sends and optional Ping/Pong handling remain scoped to the existing adapters. AB-05 adds TLS 1.3-only native Python hub configuration, TLS 1.3-only benchmark/test helper configuration, generated-certificate evidence for valid mTLS, missing client certificate, wrong client issuer, expired/not-yet-valid client and server certificates, wrong server SAN, malformed PEM, mismatched cert/key pairs, explicit TLS 1.3 negotiation, and TLS 1.2-only client rejection. The benchmark SC hub now enforces client certificates when `--ca` is supplied. Direct WebSocket connections using `dc.bsc.bacnet.org` are deferred/unsupported because direct connections are not implemented or publicly claimed. This row stays `implementation-present-needs-security-tests` until TLS 1.3 application profile/cipher-suite evidence, revocation behavior when configured, production file-path helper tests, and any optional certificate identity policy are fully evidenced; server-auth-only examples remain documented as non-conformant example/benchmark mode. |
| `BACNET-AB-SC-HEARTBEAT` | Annex AB.6.3 | P0 | `implementation-present-needs-timeout-tests` | SC heartbeat code exists; deterministic timeout tests remain open. |

## Explicit Deferred Or Unsupported Annexes

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-O-ZIGBEE` | Annex O | P3 | `unknown-pending-source-review` | No public support claim found in the initial scan. |

## Follow-Up Backlog

Rows not marked `supported-with-clause-evidence` are follow-up work. The next Annex J tranche should continue BBMD/BDT/FDT lifecycle evidence, including remaining forwarding-loop prevention negative cases and management/table edge cases. NAT traversal and B/IP-M multicast are now explicitly tracked as deferred owner-decision rows.
