"""Independent multicast observer in a second task-owned IPv6 container.

The explicit RB_IPV6_OBSERVER_BIND ULA and RB_IPV6_TEST_INDEX select its isolated
link. A TCP client supplies {"port": N}; readiness and captured datagrams are
newline JSON. TCP EOF releases that subscription. No application frames are sent.
"""
import ipaddress
import json
import os
import select
import socket
import struct

address = os.environ["RB_IPV6_OBSERVER_BIND"]
index = int(os.environ["RB_IPV6_TEST_INDEX"])
assert ipaddress.IPv6Address(address).is_private and address.startswith("fd")
assert index > 0
group = "ff05::bac0"

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
    listener.bind((address, 47809))
    listener.listen(1)
    print(json.dumps({"ready": address, "index": index}), flush=True)
    while True:
        connection, _ = listener.accept()
        with connection, connection.makefile("rb") as request:
            spec = json.loads(request.readline(128))
            port = int(spec["port"])
            assert 0 < port < 65536
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
                udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
                udp.bind((group, port))
                udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                               socket.inet_pton(socket.AF_INET6, group)
                               + struct.pack("@I", index))
                connection.sendall(json.dumps({"index": index}).encode() + b"\n")
                while True:
                    ready, _, _ = select.select([connection, udp], [], [])
                    if connection in ready:
                        assert connection.recv(1) == b"", "only EOF follows subscription"
                        break
                    data, control, flags, source = udp.recvmsg(2048, 256)
                    assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    info = [v for level, kind, v in control
                            if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO]
                    assert len(info) == 1 and len(info[0]) == 20
                    packet = {"bytes": list(data),
                              "source": f"[{source[0]}]:{source[1]}",
                              "destination": socket.inet_ntop(socket.AF_INET6, info[0][:16]),
                              "index": struct.unpack("@I", info[0][16:])[0]}
                    assert packet["destination"] == group and packet["index"] == index
                    connection.sendall(json.dumps(packet).encode() + b"\n")
