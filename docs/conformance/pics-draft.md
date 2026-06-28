# Draft BACnet PICS Support Evidence

> DRAFT internal support evidence. Generated from `conformance/bacnet-135-2020.json`; this is not a BTL certification claim or formal PICS/BIBB declaration.

This draft summarizes implementation evidence that may feed a future formal Protocol Implementation Conformance Statement. It intentionally stays below a certification claim.

## Data Link And Network Rows

| ID | Anchor | Status | Code Anchors |
|---|---|---|---|
| `BACNET-7-ETHERNET-LLC` | Clause 7 | implementation-present-needs-platform-tests | `crates/bacnet-transport/src/ethernet*`, `crates/bacnet-transport/Cargo.toml` |
| `BACNET-9-MSTP-FRAMES` | Clause 9.3 | implementation-present-needs-source-review | `crates/bacnet-transport/src/mstp_frame.rs`, `crates/bacnet-transport/src/mstp`, `crates/bacnet-transport/src/mstp/tests.rs` |
| `BACNET-J-BVLC-FUNCTION-CODES` | Annex J.2 | implementation-present-needs-conformance-tests | `crates/bacnet-transport/src/bvll.rs`, `crates/bacnet-types/src/enums/bvll.rs` |
| `BACNET-J-ORIGINAL-UNICAST-NPDU` | Annex J | implementation-present-needs-negative-tests | `crates/bacnet-transport/src/bvll.rs`, `crates/bacnet-transport/src/bip` |
| `BACNET-J-ORIGINAL-BROADCAST-NPDU` | Annex J | implementation-present-needs-negative-tests | `crates/bacnet-transport/src/bvll.rs`, `crates/bacnet-transport/src/bip` |
| `BACNET-J-FORWARDED-NPDU` | Annex J | implementation-present-needs-negative-tests | `crates/bacnet-transport/src/bvll.rs`, `crates/bacnet-transport/src/bbmd.rs` |
| `BACNET-J-BBMD-BDT` | Annex J.4/J.5 | implementation-present-needs-conformance-tests | `crates/bacnet-transport/src/bbmd.rs`, `crates/bacnet-cli/src/shell/bbmd.rs` |
| `BACNET-J-FOREIGN-DEVICE-FDT` | Annex J.5 | implementation-present-needs-conformance-tests | `crates/bacnet-transport/src/bbmd.rs`, `crates/bacnet-cli/src/shell/bbmd.rs` |
| `BACNET-U-IPV6-BVLL` | Annex U | implementation-present-needs-conformance-tests | `crates/bacnet-transport/src/bip6`, `crates/bacnet-types/src/enums/bvll.rs` |
| `BACNET-AB-SC-FRAME` | Annex AB.2 | implementation-present-needs-negative-tests | `crates/bacnet-transport/src/sc_frame.rs`, `crates/bacnet-wasm/src/sc_frame.rs` |
| `BACNET-AB-SC-HUB-CONNECTOR` | Annex AB.5 | implementation-present-needs-conformance-tests | `crates/bacnet-transport/src/sc/mod.rs`, `crates/bacnet-transport/src/sc_hub.rs` |
| `BACNET-AB-SC-WEBSOCKET-TLS` | Annex AB.7 | implementation-present-needs-security-tests | `crates/bacnet-transport/src/sc_hub.rs`, `crates/rusty-bacnet/src/tls.rs`, `crates/bacnet-wasm/src/ws_transport.rs` |
| `BACNET-AB-SC-HEARTBEAT` | Annex AB.6.3 | implementation-present-needs-timeout-tests | `crates/bacnet-transport/src/sc/mod.rs`, `crates/bacnet-transport/src/sc_frame.rs` |

## PICS/Profile Rows

| ID | Anchor | Status | Notes |
|---|---|---|---|
| `BACNET-12-OBJECT-MODEL` | Clauses 12-19 | implementation-present-needs-conformance-tests | Initial family row only; later work should split high-claim services and object families into detailed rows. |
| `BACNET-A-PICS` | Annex A | in-progress | This ledger does not claim certification. |
| `BACNET-L-PROFILES` | Annex L | in-progress | No profile certification claim is made by this seed. |
