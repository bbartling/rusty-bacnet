# BACnet Standard 135-2020 Conformance Ledger

> DRAFT internal support evidence. This ledger is not a BTL certification claim, a formal PICS, or a formal BIBB declaration.

## Scope

- Standard: ANSI/ASHRAE Standard 135-2020.
- Reviewed at: 2026-06-28.
- Repository SHA reviewed: `ccece409211cdcc85d5736e1701db928b66cfaf8`.
- Machine-readable source: `conformance/bacnet-135-2020.json`.
- Current scope: Annex J J-04 Original-Unicast/Original-Broadcast B/IP source and BBMD fanout evidence update; Original-Broadcast local Forwarded-NPDU echo removed.
- Addenda/errata status: Official BACnet Committee Standard 135-2020 addenda through 135-2020cm checked on 2026-06-28; no Annex J/BACnet/IP Original-NPDU broadcast forwarding changes found for this tranche.

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
| `BACNET-J-BVLC-FUNCTION-CODES` | Annex J.2 | P0 | `implementation-present-needs-conformance-tests` | J-01 covers Annex J.2 constants through `0x0B`, representative frames, malformed type/length, unknown function passthrough, deleted-value passthrough, and current decoder policy for extra bytes beyond BVLC Length. J-02 adds exact two-byte BVLC-Result parsing, unknown result-code passthrough, malformed result rejection, and sender/expected-function correlation for pending management responses. |
| `BACNET-J-ORIGINAL-UNICAST-NPDU` | Annex J | P0 | `implementation-present-needs-negative-tests` | J-04 Original-NPDU evidence covers UDP sender B/IP MAC delivery and self-originated frame suppression; directed reply-path integration remains open. |
| `BACNET-J-ORIGINAL-BROADCAST-NPDU` | Annex J | P0 | `implementation-present-needs-negative-tests` | J-04 Original-NPDU evidence covers BBMD Original-Broadcast local delivery, BDT/FDT Forwarded-NPDU fanout with original sender preservation, and no local Forwarded-NPDU echo. Remote/global NPDU broadcast addressing remains open. |
| `BACNET-J-FORWARDED-NPDU` | Annex J | P0 | `implementation-present-needs-negative-tests` | J-04 covers originating-address parsing, truncated-address rejection, BBMD delivery with originating B/IP source MAC, FDT fanout preserving the origin, local rebroadcast for unicast peer arrivals, directed-broadcast peer local-rebroadcast suppression, no onward forwarding to other BDT peers, and Original-Broadcast BDT/FDT Forwarded-NPDU emission. Non-BDT source rejection and DBTN multi-target fanout remain open. |
| `BACNET-J-BBMD-BDT` | Annex J.4/J.5 | P0 | `implementation-present-needs-conformance-tests` | J-03 covers read/write BDT caller paths, replacement semantics, malformed Write-BDT NAK without table mutation, self-entry insertion without overflow, and directed-broadcast forwarding target calculation. J-04 adds Forwarded-NPDU BDT mask behavior, no onward forwarding to other BDT peers, and Original-Broadcast one-peer fanout without local echo. Persistence, ACL matrix, and DBTN multi-target fanout remain open. |
| `BACNET-J-FOREIGN-DEVICE-FDT` | Annex J.5 | P0 | `implementation-present-needs-conformance-tests` | J-03 covers FDT read/register/delete caller paths, re-registration, zero-TTL and malformed TTL NAKs, exact Delete-FDT payload length, max TTL remaining-time capping, expiry purge, source exclusion, and unregistered DBTN NAK without local delivery. J-04 Original-Broadcast evidence covers one registered FDT target; multi-device forwarded fanout and timer-driven expiry integration remain open. |

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
| `BACNET-AB-SC-FRAME` | Annex AB.2 | P0 | `implementation-present-needs-negative-tests` | SC frame codecs exist in transport and WASM crates. |
| `BACNET-AB-SC-HUB-CONNECTOR` | Annex AB.5 | P0 | `implementation-present-needs-conformance-tests` | SC transport and hub paths exist. |
| `BACNET-AB-SC-WEBSOCKET-TLS` | Annex AB.7 | P0 | `implementation-present-needs-security-tests` | WebSocket/TLS paths exist; mTLS/security tests remain open. |
| `BACNET-AB-SC-HEARTBEAT` | Annex AB.6.3 | P0 | `implementation-present-needs-timeout-tests` | SC heartbeat code exists; deterministic timeout tests remain open. |

## Explicit Deferred Or Unsupported Annexes

| Row ID | Anchor | Priority | Status | Evidence |
|---|---|---|---|---|
| `BACNET-O-ZIGBEE` | Annex O | P3 | `unknown-pending-source-review` | No public support claim found in the initial scan. |

## Follow-Up Backlog

Rows not marked `supported-with-clause-evidence` are follow-up work. The next Annex J tranche should continue BBMD/BDT/FDT lifecycle evidence, including timer-driven expiry integration, multi-device forwarded fanout, BDT persistence, ACL behavior, and forwarding loop prevention.
