"""One year convention for every Date Python sees (#1501).

A Date reads with its full year, 1900..=2154, whether it is a property
value, the date of a timestamp or a date in a schedule entry, and an
unspecified year reads as 255 (rusty_bacnet.UNSPECIFIED) in all of them, as
every other unspecified date field does. PropertyValue.date and
BACnetTimeStamp.date_time take the same years and refuse any other. The time
synchronization requests set a clock, so they take only a specific date and
time and send nothing for any other.
"""

from __future__ import annotations

import asyncio
import datetime
import socket
import unittest
from typing import Any

from rusty_bacnet import (
    UNSPECIFIED,
    BACnetClient,
    BACnetServer,
    BACnetTimeStamp,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

P = PropertyIdentifier
NOON = (12, 0, 0, 0)
DATE_VALUE_1 = ObjectIdentifier(ObjectType.DATE_VALUE, 1)
AI_1 = ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)
SCHED_1 = ObjectIdentifier(ObjectType.SCHEDULE, 1)
CAL_1 = ObjectIdentifier(ObjectType.CALENDAR, 1)

# Each year octet a peer can send, and the year Python reads it as.
YEARS = ((126, 2026), (0, 1900), (254, 2154), (0xFF, 255))


def frame(apdu: bytes) -> bytes:
    """A B/IP original-unicast frame carrying `apdu` with no NPDU options."""
    payload = b"\x01\x00" + apdu
    return b"\x81\x0a" + (len(payload) + 4).to_bytes(2, "big") + payload


class Peer:
    """A device on a local socket that answers each ReadProperty with the
    octets it is given."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.address = f"127.0.0.1:{sock.getsockname()[1]}"

    async def read(self, client: BACnetClient, oid: ObjectIdentifier,
                   prop: PropertyIdentifier, index: int | None, octets: bytes) -> PropertyValue:
        loop = asyncio.get_running_loop()
        read = asyncio.ensure_future(client.read_property(self.address, oid, prop, index))
        wire, remote = await asyncio.wait_for(loop.sock_recvfrom(self.sock, 2048), 2)
        ack = bytes([0x30, wire[8], 12]) + wire[10:] + b"\x3e" + octets + b"\x3f"
        await loop.sock_sendto(self.sock, frame(ack), remote)
        return await asyncio.wait_for(read, 2)

    async def received(self) -> bytes:
        loop = asyncio.get_running_loop()
        wire, _ = await asyncio.wait_for(loop.sock_recvfrom(self.sock, 2048), 2)
        return wire


class DateYearTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind(("127.0.0.1", 0))
        sock.setblocking(False)
        self.peer = Peer(sock)
        self.client = BACnetClient(interface="127.0.0.1", port=0, apdu_timeout_ms=2000)
        await self.client.__aenter__()

        async def stop_client() -> None:
            await self.client.__aexit__(None, None, None)

        self.addAsyncCleanup(stop_client)

    async def test_a_date_reads_with_one_year_everywhere(self) -> None:
        for octet, year in YEARS:
            with self.subTest(octet=octet):
                date = bytes([octet, 12, 25, 5])
                expected = (year, 12, 25, 5)
                # A property value.
                value = await self.peer.read(self.client, DATE_VALUE_1, P.PRESENT_VALUE, None,
                                             b"\xa4" + date)
                self.assertEqual((value.tag, value.value), ("date", expected))
                self.assertEqual(value, PropertyValue.date(*expected))
                # The date of a timestamp.
                stamp = await self.peer.read(self.client, AI_1, P.EVENT_TIME_STAMPS, 1,
                                             b"\x2e\xa4" + date + b"\xb4\x08\x00\x00\x00\x2f")
                self.assertEqual(stamp.tag, "timestamp")
                self.assertEqual(stamp.value.value, (expected, (8, 0, 0, 0)))
                self.assertEqual(stamp.value,
                                 BACnetTimeStamp.date_time(expected, (8, 0, 0, 0)))
                # A date in schedule entries: an exception event's period, a
                # day's time value, the effective period and a calendar entry.
                event = await self.peer.read(
                    self.client, SCHED_1, P.EXCEPTION_SCHEDULE, 1,
                    b"\x0e\x0c" + date + b"\x0f\x2e\x2f\x39\x10")
                self.assertEqual(event.value["period"], {"kind": "date", "date": expected})
                day = await self.peer.read(
                    self.client, SCHED_1, P.WEEKLY_SCHEDULE, 1,
                    b"\x0e\xb4\x08\x00\x00\x00\xa4" + date + b"\x0f")
                [(_, entry)] = day.value
                self.assertEqual(entry.value, expected)
                period = await self.peer.read(self.client, SCHED_1, P.EFFECTIVE_PERIOD, None,
                                              b"\xa4" + date + b"\xa4" + date)
                self.assertEqual(period.value, (expected, expected))
                dates = await self.peer.read(self.client, CAL_1, P.DATE_LIST, None,
                                             b"\x0c" + date)
                self.assertEqual(dates.value, [{"kind": "date", "date": expected}])

    async def test_time_synchronization_sends_only_a_specific_date_and_time(self) -> None:
        # 2026-10-05 is a Monday (1).
        refused: list[tuple[Any, Any]] = [
            ((UNSPECIFIED, 10, 5, 1), NOON),
            ((2026, UNSPECIFIED, 5, 1), NOON),
            ((2026, 10, UNSPECIFIED, 1), NOON),
            ((2026, 10, 5, UNSPECIFIED), NOON),
            ((2026, 13, 5, 1), NOON),  # the odd months
            ((2026, 10, 32, 1), NOON),  # day 32, a month-end pattern
            ((2026, 2, 29, 7), NOON),  # no such day
            ((2026, 10, 5, 2), NOON),  # a Monday called a Tuesday
            ((126, 10, 5, 1), NOON),  # a year octet
            ((1899, 10, 5, 1), NOON),
            ((2155, 10, 5, 1), NOON),
            ((2026, 10, 5, 1), (UNSPECIFIED, 0, 0, 0)),
            ((2026, 10, 5, 1), (12, UNSPECIFIED, 0, 0)),
            ((2026, 10, 5, 1), (12, 0, UNSPECIFIED, 0)),
            ((2026, 10, 5, 1), (12, 0, 0, UNSPECIFIED)),
            ((2026, 10, 5, 1), (24, 0, 0, 0)),
        ]
        for service, send in ((6, self.client.time_synchronization),
                              (9, self.client.utc_time_synchronization)):
            for date, time in refused:
                with self.subTest(service=service, date=date, time=time):
                    with self.assertRaises(ValueError):
                        send(self.peer.address, date, time)
            for year in (2026, 1900, 2154):
                weekday = datetime.date(year, 10, 5).isoweekday()
                with self.subTest(service=service, year=year):
                    await send(self.peer.address, (year, 10, 5, weekday), (12, 34, 56, 78))
                    # The first frame since the last one checked: the refused
                    # calls sent nothing.
                    wire = await self.peer.received()
                    self.assertTrue(wire.endswith(bytes(
                        [0x10, service, 0xA4, year - 1900, 10, 5, weekday,
                         0xB4, 12, 34, 56, 78])), wire)


class LocalDateYearTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_written_date_reads_back_as_written(self) -> None:
        server = BACnetServer(9501, interface="127.0.0.1", port=0,
                              broadcast_address="127.0.0.1")
        server.add_date_value(1, "DV-1")
        await server.start()

        async def stop() -> None:
            await server.stop()

        self.addAsyncCleanup(stop)
        for _, year in YEARS:
            with self.subTest(year=year):
                written = PropertyValue.date(year, 12, 25, 5)
                await server.write_property_local(DATE_VALUE_1, P.PRESENT_VALUE, written,
                                                  source_object=None)
                read = await server.read_property(DATE_VALUE_1, P.PRESENT_VALUE)
                self.assertEqual(read, written)
                self.assertEqual(read.value, (year, 12, 25, 5))
                self.assertEqual(repr(read), f"PropertyValue.date({year}/12/25)")


class DateArgumentTests(unittest.TestCase):
    def test_every_date_constructor_takes_the_same_years(self) -> None:
        def property_value(year: int) -> Any:
            return PropertyValue.date(year, 1, 1, 1).value[0]

        def timestamp(year: int) -> Any:
            return BACnetTimeStamp.date_time((year, 1, 1, 1), (0, 0, 0, 0)).value[0][0]

        for build in (property_value, timestamp):
            with self.subTest(build=build.__name__):
                for _, year in YEARS:
                    self.assertEqual(build(year), year)
                # A year octet, or a year either side of the range, is refused.
                for year in (0, 126, 254, 256, 1899, 2155):
                    with self.assertRaises(ValueError):
                        build(year)
                for year in (-1, 65_536):
                    with self.assertRaises(OverflowError):
                        build(year)

    def test_unspecified_is_the_255_every_wildcard_field_holds(self) -> None:
        self.assertEqual(UNSPECIFIED, 255)
        self.assertEqual(
            PropertyValue.date(UNSPECIFIED, 12, 25, UNSPECIFIED).value, (255, 12, 25, 255))
        self.assertEqual(PropertyValue.time(*[UNSPECIFIED] * 4).value, (255,) * 4)
        stamp = BACnetTimeStamp.date_time((UNSPECIFIED,) * 4, (UNSPECIFIED,) * 4)
        self.assertEqual(stamp.value, ((255,) * 4, (255,) * 4))


if __name__ == "__main__":
    unittest.main()
