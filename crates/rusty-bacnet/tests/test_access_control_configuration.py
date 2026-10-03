"""Installed-artifact tests for the access-control keyword arguments.

add_access_door(door_members=...), add_access_point(access_doors=...) and
add_credential_data_input(supported_formats=...) set arrays that are
read-only over the network (#1249). add_access_point also takes the policy
count, the supported authorization modes and Priority_For_Writing, which are
read-only over the network too (#1307).
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import unittest
from pathlib import Path

import rusty_bacnet
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


# Each registration method and its keyword-only arguments.
KEYWORDS = (
    ("add_access_door", ["door_members"]),
    (
        "add_access_point",
        [
            "access_doors",
            "number_of_authentication_policies",
            "supported_authorization_modes",
            "priority_for_writing",
        ],
    ),
    ("add_credential_data_input", ["supported_formats"]),
)


def installed_stub_method(name: str) -> ast.FunctionDef:
    stub_path = Path(rusty_bacnet.__file__).with_suffix(".pyi")
    tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    server = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "BACnetServer"
    )
    return next(
        node
        for node in server.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


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


class AccessControlStubContractTests(unittest.TestCase):
    def test_runtime_and_stub_expose_the_keywords(self) -> None:
        for method_name, keywords in KEYWORDS:
            with self.subTest(method=method_name):
                parameters = inspect.signature(
                    getattr(BACnetServer, method_name)
                ).parameters
                self.assertEqual(
                    list(parameters), ["self", "instance", "name", *keywords]
                )
                for keyword in keywords:
                    self.assertIs(
                        parameters[keyword].kind, inspect.Parameter.KEYWORD_ONLY
                    )
                    self.assertIsNone(parameters[keyword].default)
                method = installed_stub_method(method_name)
                self.assertEqual(
                    [argument.arg for argument in method.args.args],
                    ["self", "instance", "name"],
                )
                self.assertEqual(
                    [argument.arg for argument in method.args.kwonlyargs], keywords
                )
                for default in method.args.kw_defaults:
                    self.assertIsInstance(default, ast.Constant)
                    self.assertIsNone(default.value)


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
            # Each element reads in the form it was given (#1310).
            self.assertEqual((await server.read_property(door, members, 1)).value, LOCK)
            self.assertEqual(
                (await server.read_property(door, members, 2)).value,
                (REMOTE_DEVICE, REMOTE_DOOR),
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
                (REMOTE_DEVICE, REMOTE_DOOR),
            )
            # The refused registrations left no object behind.
            for instance in (2, 3):
                with self.assertRaises(BacnetProtocolError) as raised:
                    await server.read_property(
                        ObjectIdentifier(ObjectType.ACCESS_POINT, instance), doors, 0
                    )
                self.assertEqual(raised.exception.error_code, ErrorCode.UNKNOWN_OBJECT.to_raw())
        finally:
            await server.stop()

    def test_point_settings_reach_the_rows_and_gate_writes(self) -> None:
        asyncio.run(self._point_settings())

    async def _point_settings(self) -> None:
        server = make_server()
        # Three policies; AUTHORIZE (0), DENY_ALL (2) and a proprietary 300;
        # doors commanded at priority 8.
        server.add_access_point(
            1,
            "Lobby",
            number_of_authentication_policies=3,
            supported_authorization_modes=[0, 2, 300],
            priority_for_writing=8,
        )
        server.add_access_point(2, "Side")
        for instance, settings in (
            (3, {"number_of_authentication_policies": 0}),
            (4, {"supported_authorization_modes": [1, 2]}),  # no AUTHORIZE
            (5, {"supported_authorization_modes": [0, 6]}),  # reserved
            (6, {"priority_for_writing": 17}),
        ):
            with self.assertRaises(BacnetProtocolError) as raised:
                server.add_access_point(instance, "Refused", **settings)
            self.assert_value_out_of_range(raised.exception)
        await server.start()
        try:
            lobby = ObjectIdentifier(ObjectType.ACCESS_POINT, 1)
            side = ObjectIdentifier(ObjectType.ACCESS_POINT, 2)
            policy = PropertyIdentifier.ACTIVE_AUTHENTICATION_POLICY
            policies = PropertyIdentifier.NUMBER_OF_AUTHENTICATION_POLICIES
            mode = PropertyIdentifier.AUTHORIZATION_MODE
            priority = PropertyIdentifier.PRIORITY_FOR_WRITING

            async def value(point: ObjectIdentifier, property: PropertyIdentifier) -> int:
                return (await server.read_property(point, property)).value

            self.assertEqual(await value(lobby, policies), 3)
            self.assertEqual(await value(lobby, priority), 8)
            self.assertEqual(
                [await value(side, p) for p in (policy, policies, mode, priority)],
                [1, 1, 0, 16],
            )

            async def write(property: PropertyIdentifier, value: PropertyValue) -> None:
                await server.write_property_local(lobby, property, value, source_object=None)

            # A point registered without supported modes takes AUTHORIZE
            # alone, so DENY_ALL (2) is refused there.
            with self.assertRaises(BacnetProtocolError) as raised:
                await server.write_property_local(
                    side, mode, PropertyValue.enumerated(2), source_object=None
                )
            self.assert_value_out_of_range(raised.exception)

            await write(policy, PropertyValue.unsigned(3))
            await write(mode, PropertyValue.enumerated(300))
            self.assertEqual(await value(lobby, policy), 3)
            self.assertEqual(await value(lobby, mode), 300)
            # Past the policy count, and a mode the point didn't declare.
            for property, refused in (
                (policy, PropertyValue.unsigned(4)),
                (mode, PropertyValue.enumerated(1)),
            ):
                with self.assertRaises(BacnetProtocolError) as raised:
                    await write(property, refused)
                self.assert_value_out_of_range(raised.exception)
            # Another datatype.
            with self.assertRaises(BacnetProtocolError) as raised:
                await write(mode, PropertyValue.unsigned(2))
            self.assertEqual(
                raised.exception.error_code, ErrorCode.INVALID_DATA_TYPE.to_raw()
            )
            for property in (policies, priority):
                with self.assertRaises(BacnetProtocolError) as raised:
                    await write(property, PropertyValue.unsigned(2))
                self.assertEqual(
                    raised.exception.error_code, ErrorCode.WRITE_ACCESS_DENIED.to_raw()
                )
            self.assertEqual(
                [await value(lobby, p) for p in (policy, policies, mode, priority)],
                [3, 3, 300, 8],
            )
        finally:
            await server.stop()

    def test_device_reference_pairs_name_a_device(self) -> None:
        asyncio.run(self._device_reference_pairs())

    async def _device_reference_pairs(self) -> None:
        server = make_server()
        # A pair's device must be a Device (#1285); the refusal registers
        # nothing.
        not_a_device = ObjectIdentifier(ObjectType.ANALOG_VALUE, 99)
        with self.assertRaises(ValueError):
            server.add_access_door(2, "Wrong", door_members=[LOCK, (not_a_device, LOCK)])
        with self.assertRaises(ValueError):
            server.add_access_point(
                2, "Wrong", access_doors=[(not_a_device, REMOTE_DOOR)]
            )
        server.add_access_door(1, "Main Entry", door_members=[(REMOTE_DEVICE, LOCK)])
        await server.start()
        try:
            members = PropertyIdentifier.DOOR_MEMBERS
            door = ObjectIdentifier(ObjectType.ACCESS_DOOR, 1)
            self.assertEqual((await server.read_property(door, members, 0)).value, 1)
            for refused in (
                ObjectIdentifier(ObjectType.ACCESS_DOOR, 2),
                ObjectIdentifier(ObjectType.ACCESS_POINT, 2),
            ):
                with self.assertRaises(BacnetProtocolError) as raised:
                    await server.read_property(
                        refused, PropertyIdentifier.OBJECT_NAME
                    )
                self.assertEqual(raised.exception.error_code, ErrorCode.UNKNOWN_OBJECT.to_raw())
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
            self.assertEqual((await server.read_property(reader, formats)).value,
                             [8, (2, 260, 7)])
            self.assertEqual((await server.read_property(reader, formats, 1)).value, 8)
            self.assertEqual(
                (await server.read_property(reader, formats, 2)).value, (2, 260, 7)
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
