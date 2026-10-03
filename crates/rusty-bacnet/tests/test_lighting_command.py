"""Installed-artifact tests for Lighting Output's Lighting_Command (#1263).

Lighting_Command reads as ``application_data`` holding the context-tagged
BACnetLightingCommand, operation NONE until written. It takes writes in that
encoding, locally and over the network. An ``octet_string``, the form it used
to take, is refused with INVALID_DATA_TYPE, and a command its operation can't
take with VALUE_OUT_OF_RANGE.
"""

from __future__ import annotations

import unittest

from rusty_bacnet import (
    BACnetClient,
    BACnetServer,
    BacnetProtocolError,
    ErrorClass,
    ErrorCode,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

LC = PropertyIdentifier.LIGHTING_COMMAND
LO = ObjectIdentifier(ObjectType.LIGHTING_OUTPUT, 1)
# Operation [0] NONE.
NONE = bytes([0x09, 0x00])
# FADE_TO (1), target level [1] 50.0 % (REAL 0x42480000), priority [5] 8.
FADE = bytes([0x09, 0x01, 0x1C, 0x42, 0x48, 0x00, 0x00, 0x59, 0x08])
# STOP (10) at priority [5] 3.
STOP = bytes([0x09, 0x0A, 0x59, 0x03])


def make_server() -> BACnetServer:
    server = BACnetServer(
        device_instance=1_263_001,
        device_name="Lighting Command Artifact Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )
    server.add_lighting_output(1, "LO-1")
    return server


class LightingCommandTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = make_server()
        await self.server.start()

        async def stop_server() -> None:
            await self.server.stop()

        self.addAsyncCleanup(stop_server)
        self.address = await self.server.local_address()
        self.client = BACnetClient(interface="127.0.0.1", port=0, apdu_timeout_ms=2000)
        await self.client.__aenter__()

        async def stop_client() -> None:
            await self.client.__aexit__(None, None, None)

        self.addAsyncCleanup(stop_client)

    async def read_both(self) -> list[PropertyValue]:
        return [
            await self.server.read_property(LO, LC),
            await self.client.read_property(self.address, LO, LC),
        ]

    async def test_reads_none_until_written(self) -> None:
        for value in await self.read_both():
            self.assertEqual(value, PropertyValue.application_data(NONE))

    async def test_commands_write_and_read_in_their_encoding(self) -> None:
        await self.client.write_property(
            self.address, LO, LC, PropertyValue.application_data(FADE)
        )
        for value in await self.read_both():
            self.assertEqual(value.tag, "application_data")
            self.assertEqual(value.value, FADE)
        await self.server.write_property_local(
            LO, LC, PropertyValue.application_data(STOP), source_object=None
        )
        for value in await self.read_both():
            self.assertEqual(value.value, STOP)
        # The value read writes back locally unchanged.
        value = await self.server.read_property(LO, LC)
        await self.server.write_property_local(LO, LC, value, source_object=None)
        self.assertEqual(await self.server.read_property(LO, LC), value)

    async def assert_refused(self, value: PropertyValue, code: ErrorCode) -> None:
        with self.assertRaises(BacnetProtocolError) as network:
            await self.client.write_property(self.address, LO, LC, value)
        with self.assertRaises(BacnetProtocolError) as local:
            await self.server.write_property_local(LO, LC, value, source_object=None)
        for raised in (network.exception, local.exception):
            self.assertEqual(raised.error_class, ErrorClass.PROPERTY.to_raw())
            self.assertEqual(raised.error_code, code.to_raw())

    async def test_octet_string_is_refused_and_changes_nothing(self) -> None:
        await self.assert_refused(PropertyValue.octet_string(FADE), ErrorCode.INVALID_DATA_TYPE)
        self.assertEqual(
            await self.server.read_property(LO, LC), PropertyValue.application_data(NONE)
        )

    async def test_command_its_operation_cannot_take_is_out_of_range(self) -> None:
        # NONE can't be written, and FADE_TO needs a target level.
        for octets in (NONE, bytes([0x09, 0x01, 0x59, 0x08])):
            with self.subTest(octets=octets.hex()):
                await self.assert_refused(
                    PropertyValue.application_data(octets), ErrorCode.VALUE_OUT_OF_RANGE
                )
        self.assertEqual(
            await self.server.read_property(LO, LC), PropertyValue.application_data(NONE)
        )


if __name__ == "__main__":
    unittest.main()
