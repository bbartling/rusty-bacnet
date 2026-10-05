# Network samples

BACnet/IP **client and server programs** that complement the single-file examples in [`examples/rust`](../). Each is a crate in the repository's Cargo workspace, with **path dependencies** on the `bacnet-*` crates.

## Samples

| Crate | Role |
|-------|------|
| [`mini-device-revisited/`](mini-device-revisited/) | BACnet **server** — 4-point test device (BACpypes3 port) |
| [`whois-scan/`](whois-scan/) | **Who-Is** scanner — list I-Am responses, exit |
| [`point-discover/`](point-discover/) | **Point discovery** — object-list, present-value, priority arrays |
| [`bacnet-write/`](bacnet-write/) | **WriteProperty** — write, verify, relinquish |
| [`rpm-read/`](rpm-read/) | **ReadPropertyMultiple** — bulk sensor read |

Helper script:

```bash
./run-with-logs.sh          # run mini-device in foreground with debug logging
```

Pass `--replace-existing` to the mini-device binary (via the script) if UDP `:47808` is already in use and you intend to take over the port.

## Typical workflow

```bash
# Terminal 1 — local test server
./run-with-logs.sh

# Terminal 2 — scan subnet (set your NIC IP / broadcast)
cd whois-scan && ./run.sh

# Terminal 3 — enumerate a device (defaults target instance 5007)
cd point-discover && ./run-5007.sh

# Terminal 4 — RPM read three sensors in one request
cd rpm-read && ./run-5007.sh

# Terminal 5 — WriteProperty demo (writes then reverts)
cd bacnet-write && ./run-5007.sh
```

Override bench defaults with environment variables (`BACNET_BIND_ADDRESS`, `BACNET_BROADCAST`, etc.) — see each crate's README.

## Same-host caveat

rusty-bacnet BIP drops frames where the source MAC equals the local bind MAC. A client on the same IP as a local server may not discover it; scan from another host when testing discovery.

Only one process should bind UDP `:47808` on a host at a time.

## Build

The samples are workspace members, left out of the workspace's default build, so pick one by package name from anywhere in the checkout (or run `cargo build --release` in its folder):

```bash
cargo build --release -p mini-device-revisited
cargo run --release -p whois-scan -- --help
```

They share the workspace's `Cargo.lock`, and binaries land in its `target/release/`. The `run.sh` / `run-5007.sh` wrappers go through `cargo run --release`, which builds the sample first when needed.
