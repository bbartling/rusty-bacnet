#!/usr/bin/env bash
# Smoke-test a release CLI binary (#943), with a Python that has the
# rusty_bacnet wheel installed:
#   scripts/release/cli_smoke.sh <bacnet-binary> <python>
#
# - --version and --help run;
# - the README quickstart on loopback: a Python server with one analog input,
#   then `read` and `--json readm` from the CLI;
# - capture --read decodes a one-packet pcap file, which exercises the
#   statically linked libpcap, including its filter compiler, without needing
#   capture privileges.
set -euo pipefail

cli=$1
python=$2
tmp=$(mktemp -d)
server=
cleanup() {
  [ -z "$server" ] || kill "$server" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

"$cli" --version
"$cli" --help >/dev/null

# The README quickstart server, unchanged.
cat >"$tmp/local_server.py" <<'EOF'
import asyncio
from rusty_bacnet import BACnetServer


async def main():
    server = BACnetServer(
        device_instance=1234,
        device_name="Local BACnet lab",
        interface="127.0.0.1",
        port=47808,
        broadcast_address="127.0.0.1",
    )
    # Units 62 = degrees Celsius. Add objects before starting the server.
    server.add_analog_input(1, "Zone temperature", units=62, present_value=22.5)
    try:
        await server.start()
        print(f"Listening at {await server.local_address()}", flush=True)
        await asyncio.Event().wait()
    finally:
        await server.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
EOF
"$python" "$tmp/local_server.py" >"$tmp/server.log" 2>&1 &
server=$!
for _ in $(seq 100); do
  grep -q '^Listening at' "$tmp/server.log" && break
  kill -0 "$server" 2>/dev/null || break
  sleep 0.1
done
grep -q '^Listening at' "$tmp/server.log" || { echo "server did not start:"; cat "$tmp/server.log"; exit 1; }

out=$("$cli" --interface 127.0.0.1 --port 0 read 127.0.0.1:47808 ai:1 pv)
echo "$out"
grep -q '22\.5' <<<"$out" || { echo "read did not return 22.5"; exit 1; }

json=$("$cli" --interface 127.0.0.1 --port 0 --json readm 127.0.0.1:47808 ai:1 pv,object-name)
echo "$json"
for want in '22.5' 'Zone temperature'; do
  grep -qF "$want" <<<"$json" || { echo "readm output lacks '$want'"; exit 1; }
done

# One Ethernet/IPv4/UDP frame to port 47808 carrying a BACnet/IP Who-Is,
# in a classic pcap file.
"$python" - "$tmp/whois.pcap" <<'EOF'
import struct, sys
bvll = bytes.fromhex("810b000c") + bytes.fromhex("0120ffff00ff") + bytes.fromhex("1008")
udp = struct.pack("!HHHH", 47808, 47808, 8 + len(bvll), 0) + bvll
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                 bytes([192, 168, 1, 10]), bytes([192, 168, 1, 255])) + udp
frame = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    f.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame)
EOF
cap=$("$cli" --json capture --read "$tmp/whois.pcap" --decode)
echo "$cap"
grep -q '"service":"WHO_IS"' <<<"$cap" || { echo "capture did not decode the Who-Is"; exit 1; }
echo "CLI smoke test passed"
