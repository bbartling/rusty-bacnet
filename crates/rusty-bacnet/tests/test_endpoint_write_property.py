"""Installed endpoint WP signature, synchronous preflight and independent wire vectors."""
import asyncio
import ast
import inspect
from pathlib import Path
import socket
import unittest

import rusty_bacnet
from rusty_bacnet import (BACnetServer, BipEndpoint, EndpointClient, BacnetError,
                         BacnetProtocolError, ObjectIdentifier, ObjectType,
                         PropertyIdentifier, PropertyValue)


class EndpointWriteTests(unittest.IsolatedAsyncioTestCase):
    async def test_required_commandability_and_synchronous_preflight_without_reporter(self):
        endpoint = BipEndpoint(device_instance=9180, interface="127.0.0.1", port=0)
        await endpoint.start()
        try:
            role = await endpoint.client()
            args = ("not-an-address", ObjectIdentifier(ObjectType.ANALOG_VALUE, 7),
                    PropertyIdentifier.PRESENT_VALUE, PropertyValue.null())
            with self.assertRaises(TypeError):
                role.write_property(*args)
            for literal in ("unknown", "Commandable", "", "false"):
                with self.assertRaisesRegex(ValueError, "commandability"):
                    role.write_property(*args, commandability=literal)
            for priority in (0, 17, 255):
                with self.assertRaisesRegex(ValueError, "priority"):
                    role.write_property(*args, priority=priority, commandability="noncommandable")
            for priority in (-1, 256):
                with self.assertRaises(OverflowError):
                    role.write_property(*args, priority=priority, commandability="commandable")
            for raw in (b"\x3e", b"\x00" * 33 + b"\x3e", b"\x00" * 2000):
                with self.assertRaises(ValueError):
                    role.write_property(*args[:3], PropertyValue.application_data(raw), commandability="noncommandable")
            self.assertEqual((await endpoint.status())["active_leases"], 0)
            self.assertIn("write_property", role.service_scope()["initiates"])
        finally:
            await endpoint.close()

    async def test_wire_value_priority_result_and_awaitable_contract(self):
        endpoint = BipEndpoint(device_instance=9181, interface="127.0.0.1", port=0)
        await endpoint.start()
        oid = ObjectIdentifier(ObjectType.ANALOG_VALUE, 7)
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0)); peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            try:
                role = await endpoint.client()
                for commandability in ("commandable", "noncommandable"):
                    for raw, priority, error in ((b"", None, False), (b"\x00", None, False),
                                                 (b"\x00" * 32, 8, False), (b"\x00" * 33, 8, False),
                                                 (b"", None, True)):
                        future = role.write_property(address, oid, PropertyIdentifier.PRESENT_VALUE,
                                                     PropertyValue.application_data(raw), priority=priority,
                                                     array_index=2, commandability=commandability)
                        self.assertTrue(inspect.isawaitable(future))
                        task = asyncio.ensure_future(future)
                        try:
                            wire, remote = await asyncio.wait_for(loop.sock_recvfrom(peer, 4096), 2)
                            self.assertEqual(wire[9], 15)
                            expected = b"\x0c" + ((2 << 22) | 7).to_bytes(4, "big") + b"\x19\x55\x29\x02\x3e" + raw + b"\x3f"
                            if priority is not None: expected += b"\x49" + bytes([priority])
                            self.assertEqual(wire[10:], expected)
                            payload = b"\x01\x00" + (b"\x50" if error else b"\x20") + bytes([wire[8], 15])
                            if error: payload += b"\x91\x02\x91\x28"
                            await loop.sock_sendto(peer, b"\x81\x0a" + (len(payload)+4).to_bytes(2,"big") + payload, remote)
                            if error:
                                with self.assertRaises(BacnetProtocolError): await asyncio.wait_for(task, 2)
                            else: self.assertIsNone(await asyncio.wait_for(task, 2))
                        finally:
                            if not task.done(): task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                await endpoint.close()
                with self.assertRaises(BacnetError):
                    await role.write_property(address, oid, PropertyIdentifier.PRESENT_VALUE, PropertyValue.null(), commandability="commandable")
            finally:
                await endpoint.close()

    async def test_real_empty_recipient_list_and_scalar_error(self):
        server = BACnetServer(9182, interface="127.0.0.1", port=0)
        server.add_notification_class(1, "empty recipients")
        server.add_analog_value(7, "scalar")
        endpoint = BipEndpoint(device_instance=9183, interface="127.0.0.1", port=0)
        await server.start(); await endpoint.start()
        try:
            role = await endpoint.client(); address = await server.local_address()
            self.assertIsNone(await role.write_property(address, ObjectIdentifier(ObjectType.NOTIFICATION_CLASS, 1),
                              PropertyIdentifier.RECIPIENT_LIST, PropertyValue.application_data(b""), commandability="noncommandable"))
            with self.assertRaises(BacnetProtocolError):
                await role.write_property(address, ObjectIdentifier(ObjectType.ANALOG_VALUE, 7),
                      PropertyIdentifier.PRESENT_VALUE, PropertyValue.application_data(b""), commandability="commandable")
        finally:
            await endpoint.close(); await server.stop()

    def test_native_signature_and_installed_stub(self):
        signature = inspect.signature(EndpointClient.write_property)
        commandability = signature.parameters["commandability"]
        self.assertEqual(commandability.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(commandability.default, inspect.Parameter.empty)
        tree = ast.parse(Path(rusty_bacnet.__file__).with_suffix(".pyi").read_text())
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "EndpointClient")
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "write_property")
        self.assertEqual(ast.unparse(method.returns), "Awaitable[None]")
        self.assertEqual([a.arg for a in method.args.kwonlyargs], ["commandability"])
        self.assertEqual(method.args.kw_defaults, [None])
        self.assertEqual(ast.unparse(method.args.kwonlyargs[0].annotation), "Literal['commandable', 'noncommandable']")
