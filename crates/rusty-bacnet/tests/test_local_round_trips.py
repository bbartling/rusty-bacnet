"""A value BACnetServer.read_property returns writes back with
write_property_local (#1296 review). The local write decodes the encoded
value as a network WriteProperty does, so any shape a network write takes
works locally too.
"""

from __future__ import annotations

import unittest
from typing import Any

from rusty_bacnet import (
    BACnetClient,
    BACnetServer,
    BacnetProtocolError,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

P = PropertyIdentifier
DEVICE = 9299
AV_1 = ObjectIdentifier(ObjectType.ANALOG_VALUE, 1)
BO_1 = ObjectIdentifier(ObjectType.BINARY_OUTPUT, 1)
BV_1 = ObjectIdentifier(ObjectType.BINARY_VALUE, 1)
MSV_1 = ObjectIdentifier(ObjectType.MULTI_STATE_VALUE, 1)
CAL_1 = ObjectIdentifier(ObjectType.CALENDAR, 1)
SCHED_1 = ObjectIdentifier(ObjectType.SCHEDULE, 1)
STG_1 = ObjectIdentifier(ObjectType.STAGING, 1)
NC_1 = ObjectIdentifier(ObjectType.NOTIFICATION_CLASS, 1)
NF_1 = ObjectIdentifier(ObjectType.NOTIFICATION_FORWARDER, 1)

DEVICE_99: Any = {"kind": "device", "object_identifier": ObjectIdentifier(ObjectType.DEVICE, 99)}

# (object, property, array index): whole and indexed reads, application- and
# context-tagged, single values, multi-field values and empty lists.
ROUND_TRIPS: list[tuple[ObjectIdentifier, PropertyIdentifier, int | None]] = [
    (SCHED_1, P.EFFECTIVE_PERIOD, None),  # a date range: two dates
    (SCHED_1, P.WEEKLY_SCHEDULE, None),  # context-tagged
    (SCHED_1, P.WEEKLY_SCHEDULE, 1),
    (STG_1, P.STAGES, None),  # REAL, BIT STRING, REAL per stage
    (STG_1, P.STAGES, 1),
    (STG_1, P.TARGET_REFERENCES, None),
    (NC_1, P.RECIPIENT_LIST, None),
    (NF_1, P.PORT_FILTER, None),
    (NF_1, P.PORT_FILTER, 2),
    (CAL_1, P.DATE_LIST, None),  # empty
    (MSV_1, P.STATE_TEXT, 2),
    (AV_1, P.DESCRIPTION, None),
    (AV_1, P.OUT_OF_SERVICE, None),
]


def make_server() -> BACnetServer:
    server = BACnetServer(DEVICE, interface="127.0.0.1", port=0, broadcast_address="127.0.0.1")
    server.add_analog_value(1, "AV-1")
    server.add_binary_output(1, "BO-1")
    server.add_binary_value(1, "BV-1")
    server.add_multistate_value(1, "MSV-1", 3)
    server.add_calendar(1, "CAL-1")
    server.add_schedule(1, "SCHED-1")
    server.add_staging(1, "STG-1", 5.0, 0.0, 62, 8,
                       [(10.0, [False, True], 1.0), (20.0, [True, True], 2.0)],
                       [BO_1, BV_1])
    server.add_notification_class(1, "NC-1", 1)
    server.add_notification_forwarder(1, "NF-1", recipients=[
        {"recipient": DEVICE_99, "process_identifier": 1},
    ], port_filter=[(0, True), (1, False)])
    return server


class LocalRoundTripTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = make_server()
        await self.server.start()

        async def stop_server() -> None:
            await self.server.stop()

        self.addAsyncCleanup(stop_server)
        # Give the Notification Class a destination through a network write.
        self.address = await self.server.local_address()
        self.client = BACnetClient(interface="127.0.0.1", port=0, apdu_timeout_ms=2000)
        await self.client.__aenter__()

        async def stop_client() -> None:
            await self.client.__aexit__(None, None, None)

        self.addAsyncCleanup(stop_client)
        recipients = await self.server.read_property(NF_1, P.RECIPIENT_LIST)
        await self.client.write_property(self.address, NC_1, P.RECIPIENT_LIST, recipients)

    async def test_a_local_read_writes_back_locally_and_over_the_network(self) -> None:
        for oid, prop, index in ROUND_TRIPS:
            with self.subTest(object=oid, property=prop, index=index):
                value = await self.server.read_property(oid, prop, index)
                await self.server.write_property_local(
                    oid, prop, value, array_index=index, source_object=None
                )
                self.assertEqual(await self.server.read_property(oid, prop, index), value)
                await self.client.write_property(
                    self.address, oid, prop, value, array_index=index
                )
                self.assertEqual(await self.server.read_property(oid, prop, index), value)

    async def test_a_local_write_is_refused_as_a_network_write_is(self) -> None:
        # An index on a property that isn't an array, and an empty value
        # where one is needed.
        for oid, prop, index, value in (
            (AV_1, P.DESCRIPTION, 1, PropertyValue.character_string("x")),
            (AV_1, P.DESCRIPTION, None, PropertyValue.list([])),
        ):
            with self.subTest(property=prop, index=index):
                with self.assertRaises(BacnetProtocolError) as local:
                    await self.server.write_property_local(
                        oid, prop, value, array_index=index, source_object=None
                    )
                with self.assertRaises(BacnetProtocolError) as network:
                    await self.client.write_property(
                        self.address, oid, prop, value, array_index=index
                    )
                self.assertEqual(
                    (local.exception.error_class, local.exception.error_code),
                    (network.exception.error_class, network.exception.error_code),
                )


if __name__ == "__main__":
    unittest.main()
