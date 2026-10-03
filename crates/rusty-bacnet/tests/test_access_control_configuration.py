"""Installed-artifact tests for the access-control array keyword arguments.

add_access_door(door_members=...), add_access_point(access_doors=...) and
add_credential_data_input(supported_formats=...) set arrays that are
read-only over the network (#1249).
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
    PropertyIdentifier,
    PropertyValue,
)

LOCK = ObjectIdentifier(ObjectType.BINARY_OUTPUT, 1)
REMOTE_DEVICE = ObjectIdentifier(ObjectType.DEVICE, 99)
REMOTE_DOOR = ObjectIdentifier(ObjectType.ACCESS_DOOR, 4)

# A BACnetDeviceObjectReference: device identifier [0] when present, object
# identifier [1].
LOCK_REFERENCE = bytes([0x1C, 0x01, 0x00, 0x00, 0x01])
REMOTE_DOOR_REFERENCE = bytes(
    [0x0C, 0x02, 0x00, 0x00, 0x63, 0x1C, 0x07, 0x80, 0x00, 0x04]
)
# Supported_Formats elements: format type [0], then vendor id [1] and vendor
# format [2] for the CUSTOM format.
WIEGAND26_FORMAT = bytes([0x09, 0x08])
VENDOR_260_FORMAT = bytes([0x09, 0x02, 0x1A, 0x01, 0x04, 0x29, 0x07])


def make_server() -> BACnetServer:
    return BACnetServer(
        device_instance=503_249,
        device_name="Access Control Configuration Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )


def factor(format_type: int, format_class: int, value: bytes) -> PropertyValue:
    """A BACnetAuthenticationFactor: format type [0], class [1], value [2]."""
    return PropertyValue.application_data(
        bytes([0x09, format_type, 0x19, format_class, 0x28 | len(value)]) + value
    )


class AccessControlConfigurationTests(unittest.TestCase):
    def assert_value_out_of_range(self, error: BacnetProtocolError) -> None:
        self.assertEqual(error.error_code, ErrorCode.VALUE_OUT_OF_RANGE.to_raw())

    def test_door_members_reach_the_array(self) -> None:
        asyncio.run(self._door_members())

    async def _door_members(self) -> None:
        server = make_server()
        server.add_access_door(
            1, "Main Entry", door_members=[LOCK, (REMOTE_DEVICE, REMOTE_DOOR)]
        )
        server.add_access_door(2, "Side Entry")
        await server.start()
        try:
            door = ObjectIdentifier(ObjectType.ACCESS_DOOR, 1)
            members = PropertyIdentifier.DOOR_MEMBERS
            self.assertEqual((await server.read_property(door, members, 0)).value, 2)
            self.assertEqual(
                (await server.read_property(door, members, 1)).value, LOCK_REFERENCE
            )
            self.assertEqual(
                (await server.read_property(door, members, 2)).value,
                REMOTE_DOOR_REFERENCE,
            )
            side = ObjectIdentifier(ObjectType.ACCESS_DOOR, 2)
            self.assertEqual((await server.read_property(side, members, 0)).value, 0)
        finally:
            await server.stop()

    def test_access_doors_reach_the_array_and_name_doors_only(self) -> None:
        asyncio.run(self._access_doors())

    async def _access_doors(self) -> None:
        server = make_server()
        server.add_access_point(1, "Lobby", access_doors=[(REMOTE_DEVICE, REMOTE_DOOR)])
        with self.assertRaises(BacnetProtocolError) as raised:
            server.add_access_point(2, "Wrong", access_doors=[LOCK])
        self.assert_value_out_of_range(raised.exception)
        with self.assertRaises(TypeError):
            server.add_access_point(3, "Malformed", access_doors=["door"])
        await server.start()
        try:
            point = ObjectIdentifier(ObjectType.ACCESS_POINT, 1)
            doors = PropertyIdentifier.ACCESS_DOORS
            self.assertEqual((await server.read_property(point, doors, 0)).value, 1)
            self.assertEqual(
                (await server.read_property(point, doors, 1)).value,
                REMOTE_DOOR_REFERENCE,
            )
            # The refused registrations left no object behind.
            for instance in (2, 3):
                with self.assertRaises(RuntimeError):
                    await server.read_property(
                        ObjectIdentifier(ObjectType.ACCESS_POINT, instance), doors, 0
                    )
        finally:
            await server.stop()

    def test_supported_formats_reach_both_arrays_and_gate_simulated_reads(self) -> None:
        asyncio.run(self._supported_formats())

    async def _supported_formats(self) -> None:
        server = make_server()
        # Wiegand 26 (8) in class 0, and vendor 260's CUSTOM (2) format 7 in
        # class 3.
        server.add_credential_data_input(
            1, "Card Reader", supported_formats=[(8, 0), ((2, 260, 7), 3)]
        )
        for formats in (
            [(2, 0)],  # CUSTOM without its vendor members
            [((8, 260, 7), 0)],  # vendor members on a standard format
            [((2, 65_536, 7), 0)],  # a vendor id past Unsigned16
            [(25, 0)],  # past the closed production
        ):
            with self.assertRaises(BacnetProtocolError) as raised:
                server.add_credential_data_input(2, "Refused", supported_formats=formats)
            self.assert_value_out_of_range(raised.exception)
        await server.start()
        try:
            reader = ObjectIdentifier(ObjectType.CREDENTIAL_DATA_INPUT, 1)
            formats = PropertyIdentifier.SUPPORTED_FORMATS
            classes = PropertyIdentifier.SUPPORTED_FORMAT_CLASSES
            self.assertEqual((await server.read_property(reader, formats, 0)).value, 2)
            self.assertEqual(
                (await server.read_property(reader, formats, 1)).value, WIEGAND26_FORMAT
            )
            self.assertEqual(
                (await server.read_property(reader, formats, 2)).value,
                VENDOR_260_FORMAT,
            )
            self.assertEqual((await server.read_property(reader, classes)).value, [0, 3])

            # Out of service a simulated read must name a declared format with
            # its class.
            await server.write_property_local(
                reader,
                PropertyIdentifier.OUT_OF_SERVICE,
                PropertyValue.boolean(True),
                source_object=None,
            )
            card = factor(2, 3, b"\xab")
            await server.write_property_local(
                reader, PropertyIdentifier.PRESENT_VALUE, card, source_object=None
            )
            self.assertEqual(
                await server.read_property(reader, PropertyIdentifier.PRESENT_VALUE),
                card,
            )
            for undeclared in (factor(9, 0, b"\x01"), factor(8, 3, b"\x01")):
                with self.assertRaises(BacnetProtocolError) as raised:
                    await server.write_property_local(
                        reader,
                        PropertyIdentifier.PRESENT_VALUE,
                        undeclared,
                        source_object=None,
                    )
                self.assert_value_out_of_range(raised.exception)
        finally:
            await server.stop()


if __name__ == "__main__":
    unittest.main()
