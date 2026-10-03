"""BACnetServer.add_group with members (#1286).

Members take the read_property_multiple spec shape and the checks of the
endpoint owners' add_group; a B/IP read serves the Group's Present_Value, a
local read returns the same value, and rpm_max_result_elements limits it.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import unittest
from pathlib import Path

import rusty_bacnet
from rusty_bacnet import (
    BACnetClient,
    BACnetServer,
    BacnetAbortError,
    BipEndpoint,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

OUT_OF_RESOURCES = 9
PV = PropertyIdentifier.PRESENT_VALUE
NAME = PropertyIdentifier.OBJECT_NAME
AI_1 = ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)
GROUP_1 = ObjectIdentifier(ObjectType.GROUP, 1)


def stub_add_group(class_name: str) -> ast.FunctionDef:
    stub_path = Path(rusty_bacnet.__file__).with_suffix(".pyi")
    tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    owner = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return next(
        node for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == "add_group"
    )


def make_server(**keywords: int) -> BACnetServer:
    return BACnetServer(
        9286,
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
        **keywords,
    )


class ServerGroupRegistrationTests(unittest.TestCase):
    def test_runtime_and_stub_match_the_endpoint_add_group(self) -> None:
        parameters = inspect.signature(BACnetServer.add_group).parameters
        self.assertEqual(list(parameters), ["self", "instance", "name", "members"])
        self.assertIs(parameters["members"].kind, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        self.assertIsNone(parameters["members"].default)
        server_stub = stub_add_group("BACnetServer")
        self.assertEqual(
            [argument.arg for argument in server_stub.args.args],
            ["self", "instance", "name", "members"],
        )
        self.assertEqual(server_stub.args.kwonlyargs, [])
        [default] = server_stub.args.defaults
        self.assertIsInstance(default, ast.Constant)
        self.assertIsNone(default.value)
        # The same members annotation as the endpoint owners'.
        endpoint_stub = stub_add_group("BipEndpoint")
        self.assertEqual(
            ast.unparse(server_stub.args.args[3].annotation),
            ast.unparse(endpoint_stub.args.args[3].annotation),
        )
        self.assertEqual(
            list(inspect.signature(BACnetServer.add_group).parameters),
            list(inspect.signature(BipEndpoint.add_group).parameters),
        )

    def test_members_are_validated_when_added(self) -> None:
        server = make_server()
        server.add_group(1, "Empty")
        server.add_group(2, "Members", [(AI_1, [(PV, None)]), (GROUP_1, [(NAME, None)])])
        self.assertEqual(server._pending_registration_count(), 2)
        past_22_bits = PropertyIdentifier.from_raw(4_194_304)
        # Each refusal names the member's position and the rule it breaks.
        for members, message in (
            ([(AI_1, [])], r"^group member 0: the member lists no properties$"),
            (
                [(AI_1, [(PV, None)]), (AI_1, [(past_22_bits, None)])],
                r"^group member 1: property identifier 4194304 is above 4194303$",
            ),
            ([(GROUP_1, [(PV, None)])], r"^group member 0: the member reports a Group"),
            ([(ObjectIdentifier(ObjectType.GLOBAL_GROUP, 1), [(PropertyIdentifier.ALL, None)])],
             r"^group member 0: the member reports a Group"),
        ):
            with self.subTest(members=members):
                with self.assertRaisesRegex(ValueError, message):
                    server.add_group(3, "Refused", members)
        # The last 22-bit identifier, and any unsigned32 index, are accepted.
        last = PropertyIdentifier.from_raw(4_194_303)
        server.add_group(4, "Edges", members=[(AI_1, [(last, 0), (PV, (1 << 32) - 1)])])
        # Indexes outside unsigned32 fail conversion, as for read_property_multiple specs.
        for index in (-1, 1 << 32):
            with self.subTest(index=index):
                with self.assertRaises(OverflowError):
                    server.add_group(3, "Refused", [(AI_1, [(PV, index)])])
        with self.assertRaises(TypeError):
            server.add_group(3, "Malformed", [AI_1])
        self.assertEqual(server._pending_registration_count(), 3)


class ServerGroupWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_present_value_is_served_one_result_per_member(self) -> None:
        server = make_server()
        server.add_analog_input(1, "AI-1", present_value=21.5)
        server.add_group(1, "Zone", [(AI_1, [(PV, None), (NAME, None)])])
        server.add_group(2, "Empty")
        await server.start()
        try:
            address = await server.local_address()
            async with BACnetClient(interface="127.0.0.1", port=0, apdu_timeout_ms=2000) as client:
                # One result per member, as read_property_multiple of the
                # members gives them (#1310); no members is an empty list.
                group = ObjectIdentifier(ObjectType.GROUP, 1)
                served = await client.read_property(address, group, PV)
                self.assertEqual(served.value, [{
                    "object_id": AI_1,
                    "results": [
                        {"property_id": PV, "array_index": None,
                         "value": PropertyValue.real(21.5), "error": None},
                        {"property_id": NAME, "array_index": None,
                         "value": PropertyValue.character_string("AI-1"), "error": None},
                    ],
                }])
                self.assertEqual(served.value, await client.read_property_multiple(
                    address, [(AI_1, [(PV, None), (NAME, None)])]))
                self.assertEqual(await server.read_property(group, PV), served)
                empty = ObjectIdentifier(ObjectType.GROUP, 2)
                self.assertEqual(await client.read_property(address, empty, PV),
                                 PropertyValue.list([]))
                self.assertEqual(await server.read_property(empty, PV), PropertyValue.list([]))
        finally:
            await server.stop()

    async def read_groups(self, **limit: int) -> list[int | None]:
        """Reads Group 1 (three rows) then Group 2 (two rows); each result is
        None when served, else the abort reason."""
        server = make_server(**limit)
        server.add_analog_input(1, "AI-1", present_value=21.5)
        server.add_group(1, "Three rows", [(AI_1, [(PV, None), (NAME, None)])])
        server.add_group(2, "Two rows", [(AI_1, [(PV, None)])])
        results: list[int | None] = []
        await server.start()
        try:
            address = await server.local_address()
            async with BACnetClient(interface="127.0.0.1", port=0, apdu_timeout_ms=2000) as client:
                for instance in (1, 2):
                    group = ObjectIdentifier(ObjectType.GROUP, instance)
                    try:
                        async with asyncio.timeout(5):
                            await client.read_property(address, group, PV)
                        results.append(None)
                    except BacnetAbortError as error:
                        results.append(error.reason)
        finally:
            await server.stop()
        return results

    async def test_rpm_max_result_elements_limits_a_group_read(self) -> None:
        self.assertEqual(
            await self.read_groups(rpm_max_result_elements=2), [OUT_OF_RESOURCES, None]
        )
        # The default, 256, serves both.
        self.assertEqual(await self.read_groups(), [None, None])


if __name__ == "__main__":
    unittest.main()
