"""A local write's array index is checked as a network WriteProperty checks
it (#1426): write_property_local, and the writes a Command makes, refuse an
index on a property that isn't an array with PROPERTY_IS_NOT_AN_ARRAY and
leave the property as it is. An index past the end of a real array is
INVALID_ARRAY_INDEX, and a valid index still writes its element.
"""

from __future__ import annotations

import asyncio
import unittest

from rusty_bacnet import (
    BACnetServer,
    BacnetProtocolError,
    ErrorCode,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier as P,
    PropertyValue,
)

AI_1 = ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)
BV_1 = ObjectIdentifier(ObjectType.BINARY_VALUE, 1)
MSV_1 = ObjectIdentifier(ObjectType.MULTI_STATE_VALUE, 1)
CMD_1 = ObjectIdentifier(ObjectType.COMMAND, 1)


def indexed(target: ObjectIdentifier, prop: P, index: int, value: str):
    return {
        "object_identifier": target,
        "property_identifier": prop,
        "property_array_index": index,
        "property_value": PropertyValue.character_string(value),
    }


def make_server() -> BACnetServer:
    server = BACnetServer(
        device_instance=1426,
        device_name="Local Array Index Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )
    server.add_analog_input(1, "AI-1")
    server.add_binary_value(1, "BV-1")
    server.add_multistate_value(1, "MSV-1", 3)
    # Description[1] is refused; State_Text[2] is written.
    server.add_command(
        1,
        "CMD-1",
        action=[
            [
                indexed(AI_1, P.DESCRIPTION, 1, "command"),
                indexed(MSV_1, P.STATE_TEXT, 2, "command"),
            ]
        ],
    )
    return server


class LocalArrayIndexTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = make_server()
        await self.server.start()

        async def stop_server() -> None:
            await self.server.stop()

        self.addAsyncCleanup(stop_server)

    async def read(self, oid, prop, index=None):
        return (await self.server.read_property(oid, prop, index)).value

    async def test_an_index_the_property_cannot_take_is_refused(self) -> None:
        cases = (
            (AI_1, P.DESCRIPTION, 1, PropertyValue.character_string("x"),
             ErrorCode.PROPERTY_IS_NOT_AN_ARRAY),
            (BV_1, P.PRESENT_VALUE, 1, PropertyValue.enumerated(1),
             ErrorCode.PROPERTY_IS_NOT_AN_ARRAY),
            (MSV_1, P.STATE_TEXT, 9, PropertyValue.character_string("x"),
             ErrorCode.INVALID_ARRAY_INDEX),
        )
        for oid, prop, index, value, code in cases:
            with self.subTest(object=oid, property=prop, index=index):
                before = await self.read(oid, prop)
                with self.assertRaises(BacnetProtocolError) as raised:
                    await self.server.write_property_local(
                        oid, prop, value, array_index=index, source_object=None
                    )
                self.assertEqual(raised.exception.error_code, code.to_raw())
                self.assertEqual(await self.read(oid, prop), before)

    async def test_a_valid_index_writes_its_element(self) -> None:
        states = await self.read(MSV_1, P.STATE_TEXT)
        await self.server.write_property_local(
            MSV_1,
            P.STATE_TEXT,
            PropertyValue.character_string("Two"),
            array_index=2,
            source_object=None,
        )
        self.assertEqual(
            await self.read(MSV_1, P.STATE_TEXT), [states[0], "Two", states[2]]
        )

    async def test_a_command_write_with_such_an_index_fails(self) -> None:
        description = await self.read(AI_1, P.DESCRIPTION)
        await self.server.write_property_local(
            CMD_1, P.PRESENT_VALUE, PropertyValue.unsigned(1), source_object=None
        )
        for _ in range(500):
            if not await self.read(CMD_1, P.IN_PROCESS):
                break
            await asyncio.sleep(0.01)
        else:
            self.fail("the Command run never ended")
        self.assertIs(await self.read(CMD_1, P.ALL_WRITES_SUCCESSFUL), False)
        commands = await self.read(CMD_1, P.ACTION, 1)
        self.assertEqual(
            [command["write_successful"] for command in commands], [False, True]
        )
        self.assertEqual(await self.read(AI_1, P.DESCRIPTION), description)
        self.assertEqual(await self.read(MSV_1, P.STATE_TEXT, 2), "command")


if __name__ == "__main__":
    unittest.main()
