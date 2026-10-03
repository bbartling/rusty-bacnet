"""Installed-artifact tests for add_command's action and action_text (#1179)."""

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

CMD = ObjectIdentifier(ObjectType.COMMAND, 1)
AO1 = ObjectIdentifier(ObjectType.ANALOG_OUTPUT, 1)
AV1 = ObjectIdentifier(ObjectType.ANALOG_VALUE, 1)
MISSING = ObjectIdentifier(ObjectType.ANALOG_OUTPUT, 9)


def write(target: ObjectIdentifier, value: float, priority: int, **extra):
    return {
        "object_identifier": target,
        "property_identifier": P.PRESENT_VALUE,
        "property_value": PropertyValue.real(value),
        "priority": priority,
        **extra,
    }


# List 1 writes AO-1 and AV-1. List 2 fails on a missing object and quits,
# so its AO-1 write is never made.
ACTION = [
    [write(AO1, 50.0, 8), write(AV1, 21.5, 9, post_delay=0)],
    [write(MISSING, 1.0, 8, quit_on_failure=True), write(AO1, 10.0, 8)],
]


def make_server() -> BACnetServer:
    return BACnetServer(
        device_instance=503_179,
        device_name="Command Actions Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )


class CommandActionTests(unittest.IsolatedAsyncioTestCase):
    async def read(self, server: BACnetServer, oid, prop, index=None):
        return (await server.read_property(oid, prop, index)).value

    async def run_list(self, server: BACnetServer, number: int) -> None:
        """Write Present_Value and wait for the run it starts to end."""
        await server.write_property_local(
            CMD, P.PRESENT_VALUE, PropertyValue.unsigned(number), source_object=None
        )
        for _ in range(500):
            if not await self.read(server, CMD, P.IN_PROCESS):
                return
            await asyncio.sleep(0.01)
        self.fail("the Command run never ended")

    async def test_present_value_write_runs_the_configured_list(self) -> None:
        server = make_server()
        server.add_analog_output(1, "AO-1")
        server.add_analog_value(1, "AV-1")
        server.add_command(1, "CMD-1", action=ACTION, action_text=["Occupied", "Fault"])
        await server.start()
        try:
            self.assertEqual(
                await self.read(server, CMD, P.ACTION_TEXT), ["Occupied", "Fault"]
            )
            self.assertEqual(await self.read(server, CMD, P.ACTION, 0), 2)

            await self.run_list(server, 1)
            self.assertEqual(await self.read(server, AO1, P.PRESENT_VALUE), 50.0)
            self.assertEqual(await self.read(server, AV1, P.PRESENT_VALUE), 21.5)
            self.assertIs(await self.read(server, CMD, P.ALL_WRITES_SUCCESSFUL), True)

            await self.run_list(server, 2)
            self.assertIs(await self.read(server, CMD, P.ALL_WRITES_SUCCESSFUL), False)
            self.assertEqual(await self.read(server, AO1, P.PRESENT_VALUE), 50.0)
        finally:
            await server.stop()

    async def test_invalid_actions_are_refused_and_add_nothing(self) -> None:
        server = make_server()
        protocol = (
            ("priority 17", {"action": [[write(AO1, 1.0, 17)]]}),
            ("one text, two lists", {"action": ACTION, "action_text": ["Only one"]}),
            ("text without lists", {"action_text": ["Orphan"]}),
        )
        for instance, (case, kwargs) in enumerate(protocol, 10):
            with self.subTest(case=case):
                with self.assertRaises(BacnetProtocolError) as raised:
                    server.add_command(instance, case, **kwargs)
                self.assertEqual(
                    raised.exception.error_code, ErrorCode.VALUE_OUT_OF_RANGE.to_raw()
                )
        unknown = dict(write(AO1, 1.0, 8), quit_on_faliure=True)
        missing = write(AO1, 1.0, 8)
        del missing["property_value"]
        shapes = (
            ("unknown key", [[unknown]], ValueError),
            ("missing key", [[missing]], ValueError),
            ("priority past an octet", [[write(AO1, 1.0, 256)]], ValueError),
            ("not a list", write(AO1, 1.0, 8), TypeError),
            ("a list of mappings", [write(AO1, 1.0, 8)], TypeError),
            ("value not a PropertyValue", [[dict(write(AO1, 1.0, 8), property_value=1.0)]], TypeError),
            ("quit flag not a bool", [[dict(write(AO1, 1.0, 8), quit_on_failure=1)]], TypeError),
        )
        for instance, (case, action, error) in enumerate(shapes, 20):
            with self.subTest(case=case):
                with self.assertRaises(error):
                    server.add_command(instance, case, action=action)
        with self.assertRaises(TypeError):
            server.add_command(30, "positional", ACTION)

        await server.start()
        try:
            for instance in (*range(10, 13), *range(20, 27), 30):
                with self.assertRaises(RuntimeError):
                    await server.read_property(
                        ObjectIdentifier(ObjectType.COMMAND, instance), P.PRESENT_VALUE
                    )
        finally:
            await server.stop()


if __name__ == "__main__":
    unittest.main()
