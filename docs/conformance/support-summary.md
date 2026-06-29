# BACnet Standard 135-2020 Support Summary

> DRAFT internal support evidence. Generated from `conformance/bacnet-135-2020.json`; this is not a BTL certification claim or formal PICS/BIBB declaration.

- Standard: ANSI/ASHRAE Standard 135-2020
- Reviewed at: 2026-06-29
- Implementation evidence SHA reviewed: `4bbff541adac97d6ba78066ea6cb4342f10a75e5`
- Scope: Annex AB.6.2.3 BACnet/SC accepting-peer duplicate Device UUID replacement at the hub.
- Addenda/errata: Local source `_spec/2020_ASHRAE_Standard-135-BACnet-Data-Communication-Protocol.pdf` was reviewed for Annex AB.6.2.2 and AB.6.2.3 duplicate Device UUID replacement, VMAC-collision NAK behavior, and initiating-peer Random-48 reselection context. The ASHRAE Standards Addenda and Errata pages were checked on 2026-06-29 for Standard 135-2020 addenda/errata through addenda bv, bx, ca, cc, cd, ce, cf, ch, ci, cj, ck, cn, cm, co, cp, cq, and cs, plus the 135-2020 base errata summary and listed addendum errata. The listed 135-2020 addenda/errata text was searched for AB.6.2, Device UUID, NODE_DUPLICATE_VMAC, VMAC collision, Random-48, Connect-Request, and Connect-Accept. Base 135-2020 errata corrects an AB.6.2.3 Disconnect-ACK peer-label typo; Addendum cc references AB.6.2.2/AB.6.2.3 for Network Port/hub-connection metadata; Addendum cp adds the Hello destination option to Connect-Request/Connect-Accept. None changes the AB.6.2.3 duplicate Device UUID or VMAC-collision transitions covered by this tranche.

## Counts

| Dimension | Value | Count |
|---|---|---|
| Priority | P0 | 14 |
| Priority | P1 | 10 |
| Priority | P2 | 5 |
| Priority | P3 | 4 |
| Status | deferred-pending-owner-decision | 2 |
| Status | implementation-present-needs-conformance-tests | 9 |
| Status | implementation-present-needs-negative-tests | 6 |
| Status | implementation-present-needs-platform-tests | 1 |
| Status | implementation-present-needs-security-tests | 1 |
| Status | implementation-present-needs-source-review | 2 |
| Status | implementation-present-needs-state-machine-audit | 3 |
| Status | implementation-present-needs-timeout-tests | 1 |
| Status | implementation-present-needs-window-tests | 1 |
| Status | in-progress | 3 |
| Status | unknown-pending-source-review | 4 |

## Ledger Rows

| ID | Anchor | Priority | Status | Public Claims |
|---|---|---|---|---|
| `BACNET-4-ARCHITECTURE` | Clause 4 | P2 | implementation-present-needs-source-review | 2 |
| `BACNET-5-TSM-CLIENT` | Clause 5.4.4 | P1 | implementation-present-needs-state-machine-audit | 2 |
| `BACNET-5-TSM-SERVER` | Clause 5.4.5 | P1 | implementation-present-needs-state-machine-audit | 1 |
| `BACNET-5-SEGMENTATION-WINDOW` | Clauses 5.2-5.4 | P1 | implementation-present-needs-window-tests | 2 |
| `BACNET-6-NPDU-CONTROL` | Clause 6.2 | P1 | implementation-present-needs-negative-tests | 1 |
| `BACNET-6-ROUTER-MESSAGES` | Clauses 6.4-6.6 | P1 | implementation-present-needs-conformance-tests | 1 |
| `BACNET-7-ETHERNET-LLC` | Clause 7 | P2 | implementation-present-needs-platform-tests | 2 |
| `BACNET-8-ARCNET` | Clause 8 | P3 | unknown-pending-source-review | 0 |
| `BACNET-9-MSTP-FRAMES` | Clause 9.3 | P2 | implementation-present-needs-source-review | 2 |
| `BACNET-10-PTP` | Clause 10 | P3 | unknown-pending-source-review | 0 |
| `BACNET-11-LONTALK` | Clause 11 | P3 | unknown-pending-source-review | 0 |
| `BACNET-12-OBJECT-MODEL` | Clauses 12-19 | P1 | implementation-present-needs-conformance-tests | 3 |
| `BACNET-20-ENCODING` | Clause 20 | P1 | implementation-present-needs-negative-tests | 2 |
| `BACNET-21-FORMAL-APDUS` | Clause 21 | P1 | implementation-present-needs-conformance-tests | 2 |
| `BACNET-A-PICS` | Annex A | P1 | in-progress | 2 |
| `BACNET-J-BVLC-FUNCTION-CODES` | Annex J.2 | P0 | implementation-present-needs-conformance-tests | 2 |
| `BACNET-J-ORIGINAL-UNICAST-NPDU` | Annex J | P0 | implementation-present-needs-negative-tests | 1 |
| `BACNET-J-ORIGINAL-BROADCAST-NPDU` | Annex J | P0 | implementation-present-needs-negative-tests | 1 |
| `BACNET-J-FORWARDED-NPDU` | Annex J | P0 | implementation-present-needs-negative-tests | 2 |
| `BACNET-J-BBMD-BDT` | Annex J.4/J.5 | P0 | implementation-present-needs-conformance-tests | 3 |
| `BACNET-J-FOREIGN-DEVICE-FDT` | Annex J.5 | P0 | implementation-present-needs-conformance-tests | 1 |
| `BACNET-J-NAT-TRAVERSAL` | Annex J.7.5 | P0 | deferred-pending-owner-decision | 0 |
| `BACNET-J-IP-MULTICAST` | Annex J.8 | P0 | deferred-pending-owner-decision | 0 |
| `BACNET-K-BIBBS` | Annex K | P1 | in-progress | 0 |
| `BACNET-L-PROFILES` | Annex L | P2 | in-progress | 0 |
| `BACNET-O-ZIGBEE` | Annex O | P3 | unknown-pending-source-review | 0 |
| `BACNET-U-IPV6-BVLL` | Annex U | P2 | implementation-present-needs-conformance-tests | 2 |
| `BACNET-AB-SC-FRAME` | Annex AB.2 | P0 | implementation-present-needs-negative-tests | 2 |
| `BACNET-AB-SC-BVLC-RESULT` | Annex AB.2.4 | P0 | implementation-present-needs-conformance-tests | 2 |
| `BACNET-AB-SC-CONNECTION-STATE` | Annex AB.6.2 | P0 | implementation-present-needs-state-machine-audit | 2 |
| `BACNET-AB-SC-HUB-CONNECTOR` | Annex AB.5 | P0 | implementation-present-needs-conformance-tests | 2 |
| `BACNET-AB-SC-WEBSOCKET-TLS` | Annex AB.7 | P0 | implementation-present-needs-security-tests | 2 |
| `BACNET-AB-SC-HEARTBEAT` | Annex AB.6.3 | P0 | implementation-present-needs-timeout-tests | 2 |

## Follow-Up Source

Rows not marked `supported-with-clause-evidence` are the initial follow-up backlog. Later PRs should split broad family rows into smaller clause-backed rows before strengthening public support claims.
