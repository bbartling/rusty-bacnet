# Isolated IPv6 selected-link qualification

These are external network qualification targets, not normal CI tests. The eight
single-link Rust cases and one two-link case carry explicit `#[ignore]` reasons;
invoking them without the required environment fails. Ordinary selector and
packet-metadata unit tests run normally. Do not point these fixtures at a LAN.

Use an isolated Linux environment with a task-owned internal IPv6 bridge and one
concrete ULA on its interface. Set `RB_IPV6_TEST_ADDRESS` to that address and
`RB_IPV6_TEST_INDEX` to its actual nonzero OS interface index. Run:

```sh
cargo test -p bacnet-transport --features ipv6 --locked \
  --test ipv6_selected_link -- --ignored --nocapture
```

The fixture uses the actual transport, independent raw BVLC bytes and `recvmsg`
metadata. It covers auto/explicit source identity, actual ephemeral port,
FF02/05/08 send/receive, AR/VAR controls, random reseeding and configured collision
failure, cancel/restart/stop/drop, and foreign registration/DBTN/unicast source
plus trusted/untrusted BBMD handling. Identical queued collision probes do not
establish reseeding: a distinct next VMAC must appear within the original deadline.

For the second-link negative, attach a second task-owned internal IPv6 bridge.
Set `RB_IPV6_OTHER_ADDRESS` and `RB_IPV6_OTHER_INDEX` for its different ULA/index,
then run this separate target (the automatic single-link cases are inapplicable):

```sh
cargo test -p bacnet-transport --features ipv6 --locked \
  --test ipv6_selected_link_multi -- --ignored --nocapture
```

That target requires ambiguous automatic startup to fail. An explicit link must
ignore other-link multicast and a different local unicast destination before
NPDU admission or VMAC learning; selected-link traffic still works.

On macOS, only the dedicated own-port fixture is qualified on `lo0`. Supply its
actual index, address `::1`, and `RB_IPV6_LOOPBACK_ONLY=1`, then add the filter
`explicit_own_port_peer` to the first command. This proves multicast intake and
unicast/control source metadata. It does not capture multicast egress independently.
The Linux shared-port raw observer is not a portable macOS socket-sharing oracle.

For Python, freshly build and install the extension into an isolated Linux venv
(`maturin develop --locked --uv` from `crates/rusty-bacnet`, with `VIRTUAL_ENV` and
`PYO3_PYTHON` set). From outside the checkout, use that interpreter to run the
absolute path to `crates/rusty-bacnet/tests/qualifications/ipv6_selected_link.py`
with the single-link environment above. This standalone qualification file is
not collected by normal pytest. Four cases exercise public default/explicit
server multicast Who-Is → directed I-Am and client global Who-Is → independent
I-Am discovery. It prints the loaded extension's hash before/after execution.

These checks do not qualify routed site/organization reachability, a physical
link-local deployment, Windows runtime, or full Annex U conformance. Windows
source is compile-checked separately; deployment/runtime qualification remains
in [issue #885 (project access required)](https://gitlab.com/justinscott-group/rusty-bacnet/-/work_items/885).
