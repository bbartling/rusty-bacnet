"""Installed-artifact tests for add_elevator_group's machine_room_id argument."""

from __future__ import annotations

import asyncio
import unittest

from rusty_bacnet import (
    BACnetServer,
    BacnetProtocolError,
    ErrorCode,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
)

NO_ROOM = ObjectIdentifier(ObjectType.POSITIVE_INTEGER_VALUE, 4_194_303)


def make_server() -> BACnetServer:
    return BACnetServer(
        device_instance=503_023,
        device_name="Machine Room Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )


class ElevatorGroupMachineRoomTests(unittest.TestCase):
    def test_machine_room_id_is_served_and_validated(self) -> None:
        asyncio.run(self._exercise())

    async def _exercise(self) -> None:
        server = make_server()
        room = ObjectIdentifier(ObjectType.POSITIVE_INTEGER_VALUE, 5)
        server.add_elevator_group(1, "Default")
        server.add_elevator_group(2, "Explicit", machine_room_id=room)
        with self.assertRaises(BacnetProtocolError) as raised:
            server.add_elevator_group(
                3,
                "Wrong type",
                machine_room_id=ObjectIdentifier(ObjectType.ANALOG_VALUE, 5),
            )
        self.assertEqual(
            raised.exception.error_code, ErrorCode.VALUE_OUT_OF_RANGE.to_raw()
        )

        await server.start()
        try:
            for instance, expected in ((1, NO_ROOM), (2, room)):
                value = await server.read_property(
                    ObjectIdentifier(ObjectType.ELEVATOR_GROUP, instance),
                    PropertyIdentifier.MACHINE_ROOM_ID,
                )
                self.assertEqual(value.value, expected)
            # The refused registration left no object behind.
            with self.assertRaises(RuntimeError):
                await server.read_property(
                    ObjectIdentifier(ObjectType.ELEVATOR_GROUP, 3),
                    PropertyIdentifier.MACHINE_ROOM_ID,
                )
        finally:
            await server.stop()


if __name__ == "__main__":
    unittest.main()
