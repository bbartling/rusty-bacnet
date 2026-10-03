"""BACnetServer(time_sync_policy=...) (#1292).

The keyword is checked at construction like the Rust builder checks the
policy, and a running B/IP server applies the allowlist and the step cap to
TimeSynchronization and UTCTimeSynchronization requests sent from raw sockets.
The Device's Local_Date and Local_Time, read over the network, show which
requests set the clock.
"""

from __future__ import annotations

import ast
import asyncio
import datetime
import inspect
import socket
import unittest
from pathlib import Path

import rusty_bacnet
from rusty_bacnet import BACnetClient, BACnetServer, ObjectIdentifier, ObjectType, PropertyIdentifier

DEVICE = 9292
TIME_SYNCHRONIZATION = 6
UTC_TIME_SYNCHRONIZATION = 9
UTC = datetime.timezone.utc


def time_sync_frame(when: datetime.datetime, *, service: int = TIME_SYNCHRONIZATION,
                    routed: tuple[int, bytes] | None = None) -> bytes:
    """An unconfirmed time sync carrying `when` as Date then Time, optionally
    with a routed source (SNET, SADR)."""
    date = bytes([0xA4, when.year - 1900, when.month, when.day, when.isoweekday()])
    time = bytes([0xB4, when.hour, when.minute, when.second, when.microsecond // 10_000])
    if routed is None:
        npdu = b"\x01\x00"
    else:
        network, address = routed
        npdu = b"\x01\x08" + network.to_bytes(2, "big") + bytes([len(address)]) + address
    npdu += bytes([0x10, service]) + date + time
    return b"\x81\x0a" + (len(npdu) + 4).to_bytes(2, "big") + npdu


def udp_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    return sock


def mac(sock: socket.socket) -> bytes:
    """The B/IP MAC a socket sends from: IPv4 address, then UDP port."""
    host, port = sock.getsockname()
    return socket.inet_aton(host) + port.to_bytes(2, "big")


class TimeSyncPolicyConstructorTests(unittest.TestCase):
    def test_keyword_only_default_and_stub(self) -> None:
        parameter = inspect.signature(BACnetServer).parameters["time_sync_policy"]
        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(parameter.default)
        stub_path = Path(rusty_bacnet.__file__).with_suffix(".pyi")
        tree = ast.parse(stub_path.read_text(encoding="utf-8"))
        server = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef) and node.name == "BACnetServer")
        init = next(node for node in server.body
                    if isinstance(node, ast.FunctionDef) and node.name == "__init__")
        arguments = {argument.arg: argument for argument in init.args.kwonlyargs}
        self.assertEqual(ast.unparse(arguments["time_sync_policy"].annotation),
                         "TimeSyncPolicy | None")
        # The stub lists the runtime parameters in order, with their kinds.
        runtime = [(name, p.kind) for name, p in inspect.signature(BACnetServer).parameters.items()]
        stub = [
            *((a.arg, inspect.Parameter.POSITIONAL_OR_KEYWORD) for a in init.args.args[1:]),
            *((a.arg, inspect.Parameter.KEYWORD_ONLY) for a in init.args.kwonlyargs),
        ]
        self.assertEqual(stub, runtime)

    def test_the_rust_limits_are_checked_at_construction(self) -> None:
        BACnetServer(DEVICE, time_sync_policy={})
        BACnetServer(DEVICE, time_sync_policy={
            "source_restriction": [(None, bytes(18)), (1, b"\x01"), (65534, bytes(18))] * 85,
            "max_step_ms": 0,
            "per_source_rate": (0.1, 1),
            "global_rate": (10, 4),
            "max_sources": 65536,
        })
        for policy, message in (
            ({"source_restriction": [(None, b"")]}, "1..=18 octets"),
            ({"source_restriction": [(None, bytes(19))]}, "1..=18 octets"),
            ({"source_restriction": [(7, bytes(19))]}, "1..=18 octets"),
            ({"source_restriction": [(0, b"\x01")]}, "network must be 1..=65534"),
            ({"source_restriction": [(65535, b"\x01")]}, "network must be 1..=65534"),
            ({"source_restriction": [(None, b"\x01")] * 257}, "at most 256 entries"),
            ({"per_source_rate": (0.0, 1)}, "positive and finite"),
            ({"global_rate": (float("nan"), 1)}, "positive and finite"),
            ({"global_rate": (1.0, 0)}, "positive burst"),
            ({"max_sources": 0}, "max_sources must be 1..=65536"),
            ({"max_sources": 65537}, "max_sources must be 1..=65536"),
        ):
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(ValueError, message):
                    BACnetServer(DEVICE, time_sync_policy=policy)
        for policy, error in (
            ({"max_step": 1}, TypeError),
            ({"enabled": 1}, TypeError),
            ({"source_restriction": [b"\x01"]}, TypeError),
            ({"max_step_ms": -1}, OverflowError),
            ({"source_restriction": [(70000, b"\x01")]}, OverflowError),
        ):
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(error, "time_sync_policy"):
                    BACnetServer(DEVICE, time_sync_policy=policy)


class TimeSyncPolicyWireTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, policy: dict) -> None:
        self.server = BACnetServer(DEVICE, interface="127.0.0.1", port=0,
                                   broadcast_address="127.0.0.1", time_sync_policy=policy)
        await self.server.start()

        async def stop() -> None:
            await self.server.stop()

        self.addAsyncCleanup(stop)
        self.address = await self.server.local_address()
        self.client = BACnetClient(interface="127.0.0.1", port=0)
        await self.client.__aenter__()

        async def close() -> None:
            await self.client.__aexit__(None, None, None)

        self.addAsyncCleanup(close)
        self.admitted = await self.settled(0)

    async def settled(self, admitted: int) -> int:
        """Wait until at least `admitted` unconfirmed requests were admitted
        and none is still running; return the admitted total."""
        async with asyncio.timeout(3):
            while True:
                counters = await self.server.request_admission_counters()
                if (counters["unconfirmed_admitted_total"] >= admitted
                        and counters["unconfirmed_active"] == 0):
                    return counters["unconfirmed_admitted_total"]
                await asyncio.sleep(0.01)

    async def send(self, sock: socket.socket, frame: bytes) -> None:
        """Send one time sync and wait until the server has handled it."""
        ip, port = self.address.rsplit(":", 1)
        await asyncio.get_running_loop().sock_sendto(sock, frame, (ip, int(port)))
        self.admitted = await self.settled(self.admitted + 1)

    async def clock(self) -> datetime.datetime:
        """The server's Local_Date and Local_Time; its clock runs on UTC."""
        device = ObjectIdentifier(ObjectType.DEVICE, DEVICE)
        date = (await self.client.read_property(self.address, device,
                                                PropertyIdentifier.LOCAL_DATE)).value
        time = (await self.client.read_property(self.address, device,
                                                PropertyIdentifier.LOCAL_TIME)).value
        return datetime.datetime(date[0] + 1900, date[1], date[2], time[0], time[1], time[2],
                                 time[3] * 10_000, tzinfo=UTC)

    async def test_an_allowlist_takes_only_its_listed_sources(self) -> None:
        listed, unlisted = udp_socket(), udp_socket()
        self.addCleanup(listed.close)
        self.addCleanup(unlisted.close)
        await self.start({"source_restriction": [(None, mac(listed)), (7, b"\x2a")]})
        day = lambda year: datetime.datetime(year, 2, 3, 10, 0, tzinfo=UTC)  # noqa: E731

        # An unlisted direct source, and routed sources the list doesn't name.
        for sock, routed in ((unlisted, None), (listed, (7, b"\x2b")), (listed, (8, b"\x2a"))):
            with self.subTest(routed=routed):
                await self.send(sock, time_sync_frame(day(2001), routed=routed))
                self.assertNotEqual((await self.clock()).year, 2001)
        # The listed routed source, even through an unlisted router MAC.
        await self.send(unlisted, time_sync_frame(day(2002), routed=(7, b"\x2a")))
        self.assertEqual((await self.clock()).date(), datetime.date(2002, 2, 3))
        # The listed direct source, in either service.
        await self.send(listed, time_sync_frame(day(2003)))
        self.assertEqual((await self.clock()).date(), datetime.date(2003, 2, 3))
        await self.send(listed, time_sync_frame(day(2004), service=UTC_TIME_SYNCHRONIZATION))
        self.assertEqual((await self.clock()).date(), datetime.date(2004, 2, 3))

    async def test_a_step_past_the_cap_is_refused(self) -> None:
        sock = udp_socket()
        self.addCleanup(sock.close)
        await self.start({"max_step_ms": 3_600_000})
        tolerance = datetime.timedelta(minutes=5)
        self.assertLess(abs(await self.clock() - datetime.datetime.now(UTC)), tolerance)

        # Two hours ahead is past the one-hour cap, in either service.
        for service in (TIME_SYNCHRONIZATION, UTC_TIME_SYNCHRONIZATION):
            with self.subTest(service=service):
                ahead = datetime.datetime.now(UTC) + datetime.timedelta(hours=2)
                await self.send(sock, time_sync_frame(ahead, service=service))
                self.assertLess(abs(await self.clock() - datetime.datetime.now(UTC)), tolerance)
        # Thirty minutes ahead is within it.
        ahead = datetime.timedelta(minutes=30)
        await self.send(sock, time_sync_frame(datetime.datetime.now(UTC) + ahead,
                                              service=UTC_TIME_SYNCHRONIZATION))
        self.assertLess(abs(await self.clock() - datetime.datetime.now(UTC) - ahead), tolerance)

    async def test_without_a_policy_every_valid_request_sets_the_clock(self) -> None:
        sock = udp_socket()
        self.addCleanup(sock.close)
        await self.start({})
        await self.send(sock, time_sync_frame(datetime.datetime(2001, 2, 3, 10, tzinfo=UTC),
                                              routed=(9, b"\x01")))
        self.assertEqual((await self.clock()).date(), datetime.date(2001, 2, 3))


if __name__ == "__main__":
    unittest.main()
