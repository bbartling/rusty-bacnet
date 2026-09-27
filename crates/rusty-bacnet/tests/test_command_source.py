"""Installed Python local-source API and six-family typed command state."""
import ast
import inspect
from pathlib import Path
import unittest

import rusty_bacnet
from rusty_bacnet import (
    BACnetServer, BacnetProtocolError, ObjectIdentifier, ObjectType,
    PropertyIdentifier as P, PropertyValue,
)


class CommandSourceTests(unittest.IsolatedAsyncioTestCase):
    def test_required_keyword_matches_installed_stub(self):
        parameter = inspect.signature(BACnetServer.write_property_local).parameters["source_object"]
        self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)
        tree = ast.parse(Path(rusty_bacnet.__file__).with_suffix(".pyi").read_text())
        server = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "BACnetServer")
        method = next(n for n in server.body if isinstance(n, ast.FunctionDef) and n.name == "write_property_local")
        self.assertEqual(ast.unparse(method.returns), "Awaitable[None]")
        index = next(i for i, arg in enumerate(method.args.kwonlyargs) if arg.arg == "source_object")
        self.assertIsNone(method.args.kw_defaults[index])
        self.assertEqual(ast.unparse(method.args.kwonlyargs[index].annotation), "Optional[ObjectIdentifier]")

    async def test_six_family_local_source_owner_and_atomic_correction(self):
        server = BACnetServer(824, interface="127.0.0.1", port=0)
        families = (
            (ObjectType.ANALOG_OUTPUT, server.add_analog_output, PropertyValue.real(2.0), ()),
            (ObjectType.ANALOG_VALUE, server.add_analog_value, PropertyValue.real(2.0), ()),
            (ObjectType.BINARY_OUTPUT, server.add_binary_output, PropertyValue.enumerated(1), ()),
            (ObjectType.BINARY_VALUE, server.add_binary_value, PropertyValue.enumerated(1), ()),
            (ObjectType.MULTI_STATE_OUTPUT, server.add_multistate_output, PropertyValue.unsigned(2), (3,)),
            (ObjectType.MULTI_STATE_VALUE, server.add_multistate_value, PropertyValue.unsigned(2), (3,)),
        )
        for index, (_, add, _, args) in enumerate(families, 1):
            add(index, f"tracked-{index}", *args)
        await server.start()
        try:
            for index, (kind, _, value, _) in enumerate(families, 1):
                oid = ObjectIdentifier(kind, index)
                before = await server.read_property(oid, P.PRESENT_VALUE)
                with self.assertRaises(TypeError):
                    server.write_property_local(oid, P.PRESENT_VALUE, value)
                self.assertEqual(await server.read_property(oid, P.PRESENT_VALUE), before)
                await server.write_property_local(oid, P.PRESENT_VALUE, value, priority=8, source_object=oid)
                expected = b"\x1e\x1c" + ((kind.to_raw() << 22) | index).to_bytes(4, "big") + b"\x1f"
                source = await server.read_property(oid, P.VALUE_SOURCE)
                self.assertEqual(source.tag, "application_data")
                self.assertEqual(source.value, expected)
                self.assertEqual((await server.read_property(oid, P.VALUE_SOURCE_ARRAY, array_index=0)).value, 16)
                self.assertEqual((await server.read_property(oid, P.VALUE_SOURCE_ARRAY, array_index=8)).value, expected)
                self.assertEqual((await server.read_property(oid, P.LAST_COMMAND_TIME)).value, b"\x19\x01")
                # Another local initiator has the same Device owner. Correction has no clock tick.
                await server.write_property_local(oid, P.VALUE_SOURCE, PropertyValue.application_data(b"\x08"), priority=8, source_object=None)
                self.assertEqual((await server.read_property(oid, P.VALUE_SOURCE)).value, b"\x08")
                for data in (b"\x08\x08", b"\x1e"):
                    with self.assertRaises(BacnetProtocolError):
                        await server.write_property_local(oid, P.VALUE_SOURCE, PropertyValue.application_data(data), priority=8, source_object=None)
                with self.assertRaises(BacnetProtocolError):
                    await server.write_property_local(oid, P.PRESENT_VALUE, value, source_object=ObjectIdentifier(ObjectType.ANALOG_VALUE, 999))
                self.assertEqual((await server.read_property(oid, P.VALUE_SOURCE)).value, b"\x08")
                self.assertEqual((await server.read_property(oid, P.LAST_COMMAND_TIME)).value, b"\x19\x01")
        finally:
            await server.stop()
