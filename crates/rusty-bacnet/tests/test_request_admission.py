"""Installed native artifact admission tests; loopback UDP only, no hardware."""
from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import socket
import unittest
from pathlib import Path
from typing import Any

import rusty_bacnet
from rusty_bacnet import BACnetServer


FIELDS = {
    "recovery_active", "recovery_admitted_total", "recovery_overloaded_total",
    "confirmed_global_overloaded_total", "confirmed_peer_overloaded_total",
    "unconfirmed_global_overloaded_total", "unconfirmed_peer_overloaded_total",
    "confirmed_active", "confirmed_admitted_total", "confirmed_overloaded_total",
    "confirmed_shutdown_rejected_total", "unconfirmed_active",
    "unconfirmed_admitted_total", "unconfirmed_overloaded_total",
    "unconfirmed_shutdown_rejected_total", "abort_active", "abort_admitted_total",
    "confirmed_fallback_dropped_total", "abort_shutdown_rejected_total",
}


class AdmissionSignatureTests(unittest.TestCase):
    def test_installed_stub_defaults_keyword_only_and_counter_fields(self):
        stub = Path(rusty_bacnet.__file__).with_suffix(".pyi")
        tree = ast.parse(stub.read_text())
        classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
        server = classes["BACnetServer"]
        constructor = next(n for n in server.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
        defaults = dict(zip((a.arg for a in constructor.args.kwonlyargs), constructor.args.kw_defaults))
        signature = inspect.signature(BACnetServer)
        for name, value in [("max_confirmed_in_flight", 64), ("max_unconfirmed_in_flight", 32),
                            ("max_confirmed_in_flight_per_peer", 16), ("max_unconfirmed_in_flight_per_peer", 8),
                            ("confirmed_recovery_reserve", 4), ("max_recovery_in_flight_per_peer", 1)]:
            self.assertEqual(signature.parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertEqual(signature.parameters[name].default, value)
            default = defaults[name]
            assert default is not None
            self.assertEqual(ast.literal_eval(default), value)
        fields = {n.target.id for n in classes["RequestAdmissionCounters"].body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)}
        self.assertEqual(fields, FIELDS)
        method = next(n for n in server.body if isinstance(n, ast.FunctionDef) and n.name == "request_admission_counters")
        assert method.returns is not None
        self.assertEqual(ast.unparse(method.returns), "Awaitable[RequestAdmissionCounters]")

    def test_invalid_limits_rejected_at_constructor_for_all_transports(self):
        for transport in ["bip", "ipv6", "sc", "mstp"]:
            for name in ["max_confirmed_in_flight", "max_unconfirmed_in_flight",
                         "max_confirmed_in_flight_per_peer", "max_unconfirmed_in_flight_per_peer"]:
                for value, error in [(0, ValueError), (-1, OverflowError), (1 << 200, OverflowError), ((1 << 64) - 1, ValueError)]:
                    with self.subTest(transport=transport, name=name, value=value):
                        with self.assertRaises(error):
                            invalid: dict[str, Any] = {name: value}
                            BACnetServer(123, transport=transport, **invalid)
                with self.assertRaises(TypeError):
                    invalid = {name: 1.5}
                    BACnetServer(123, transport=transport, **invalid)
                valid: dict[str, Any] = {name: 2}
                if name == "max_confirmed_in_flight":
                    valid["confirmed_recovery_reserve"] = 0
                BACnetServer(123, transport=transport, **valid,
                             sc_device_uuid=bytes.fromhex("8e62ac46d7084226913776a32b619315"),
                             sc_ca_cert="ca.pem", sc_client_cert="cert.pem", sc_client_key="key.pem")


def packet(apdu: bytes) -> bytes:
    # Original-Unicast-NPDU, local normal-priority NPDU, independent APDU bytes.
    npdu = b"\x01\x00" + apdu
    return b"\x81\x0a" + (4 + len(npdu)).to_bytes(2, "big") + npdu


def dispatched(counters) -> int:
    """Confirmed requests that reached admission, whichever way it went."""
    return counters["confirmed_admitted_total"] + counters["confirmed_overloaded_total"]


# Requests sent before waiting for the server to dispatch them all: about
# 4.3 KB of datagrams, which fits whole in any OS's default UDP receive buffer
# and in the transport's 256-slot ingress queues, so none is dropped.
WINDOW = 8
# The recovery probe's invoke ID; the burst uses the IDs below it.
PROBE = 250


class AdmissionRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = BACnetServer(123, interface="127.0.0.1", port=0,
                                  broadcast_address="127.0.0.1",
                                  max_confirmed_in_flight=1, max_unconfirmed_in_flight=2,
                                  confirmed_recovery_reserve=0)
        self.server.add_analog_value(1, "Admission AV")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.loop = asyncio.get_running_loop()
        self.replies: asyncio.Queue[bytes] = asyncio.Queue()
        self.reader: asyncio.Task[None] | None = None

    async def asyncTearDown(self):
        if self.reader is not None:
            self.reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.reader
        await self.server.stop()
        self.sock.close()

    async def send(self, apdu):
        await self.loop.sock_sendto(self.sock, packet(apdu), self.address)

    async def read_replies(self):
        # Keep the client socket drained so no reply is lost to a full buffer.
        while True:
            wire, _ = await self.loop.sock_recvfrom(self.sock, 2048)
            self.replies.put_nowait(wire)

    async def reply_until(self, predicate):
        async with asyncio.timeout(2):
            while True:
                wire = await self.replies.get()
                self.assertEqual(wire[:2], b"\x81\x0a")
                self.assertEqual(int.from_bytes(wire[2:4], "big"), len(wire))
                self.assertEqual(wire[4], 1)
                if predicate(wire[6:]):
                    return wire[6:]

    async def counters_until(self, predicate):
        async with asyncio.timeout(2):
            while True:
                counters = await self.server.request_admission_counters()
                self.assertEqual(set(counters), FIELDS)
                self.assertTrue(all(type(v) is int and v >= 0 for v in counters.values()))
                if predicate(counters):
                    return counters
                await asyncio.sleep(0)

    async def test_prestart_stopped_errors_and_zero_start_snapshot(self):
        with self.assertRaisesRegex(RuntimeError, "server not started"):
            await self.server.request_admission_counters()
        await self.server.start()
        counters = await self.server.request_admission_counters()
        self.assertEqual(set(counters), FIELDS)
        self.assertTrue(all(v == 0 for v in counters.values()))
        await self.server.stop()
        with self.assertRaisesRegex(RuntimeError, "server not started"):
            await self.server.request_admission_counters()

    async def test_real_udp_overload_counters_and_recovery(self):
        await self.server.start()
        ip, port = (await self.server.local_address()).rsplit(":", 1)
        self.address = (ip, int(port))
        self.reader = asyncio.create_task(self.read_replies())
        # Windows of back-to-back RPMs on loopback UDP, until one overloads the
        # single confirmed slot. Idle active counts alone don't end a burst:
        # they also occur while later requests still wait in the server's
        # socket buffer or ingress queue, and a probe sent then is overloaded
        # behind them (#991). Each window fits there whole and every invoke ID
        # is distinct, so no request is dropped or taken for a duplicate, and
        # once admitted + overloaded equals the number sent, the server has
        # dispatched every request.
        body = b"\x0c\x02\x00\x00\x7b\x1e" + b"\x09\x4d" * 256 + b"\x1f"
        sent = 0
        while sent + WINDOW <= PROBE:
            for _ in range(WINDOW):
                await self.send(bytes([0, 5, sent, 14]) + body)
                sent += 1
            counters = await self.counters_until(lambda c: dispatched(c) == sent)
            self.assertLessEqual(counters["confirmed_active"], 1)
            if counters["confirmed_overloaded_total"]:
                break
        self.assertGreater(counters["confirmed_overloaded_total"], 0)
        self.assertGreater(counters["confirmed_admitted_total"], 0)
        # The first overload always finds one of the 8 Abort workers free.
        self.assertGreater(counters["abort_admitted_total"], 0)
        self.assertLessEqual(counters["abort_active"], 8)
        # At least one resource Abort is observable on the actual local wire.
        await self.reply_until(lambda r: r[0] == 0x71 and r[2] == 9)
        # Nothing is left to dispatch, so idle counts now mean the slot is free.
        idle = await self.counters_until(lambda c: c["confirmed_active"] == c["abort_active"] == 0)
        await self.send(bytes([0, 5, PROBE, 12]))
        response = await self.reply_until(lambda r: r[1] == PROBE)
        self.assertEqual(response[0] >> 4, 5)  # Error proves normal handler execution.
        counters = await self.counters_until(lambda c: c["confirmed_active"] == c["abort_active"] == 0)
        self.assertEqual(dispatched(counters), sent + 1)
        self.assertEqual(counters["confirmed_admitted_total"], idle["confirmed_admitted_total"] + 1)
        self.assertEqual(counters["confirmed_overloaded_total"],
                         counters["abort_admitted_total"] + counters["confirmed_fallback_dropped_total"])
