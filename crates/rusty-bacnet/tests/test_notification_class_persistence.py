"""A Notification Class's Recipient_List kept across a restart (#1315)."""
import ast
import asyncio
import inspect
import tempfile
import unittest
from pathlib import Path

import rusty_bacnet
from rusty_bacnet import (
    BACnetClient, BACnetServer, BacnetError, BacnetProtocolError, ErrorClass, ErrorCode,
    ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
)

POSITIONAL = inspect.Parameter.POSITIONAL_OR_KEYWORD
PARAMETERS = [
    ("instance", POSITIONAL),
    ("name", POSITIONAL),
    ("notification_class", POSITIONAL),
    ("storage_path", POSITIONAL),
]

# One destination: Device 99, every day, all day, every transition,
# unconfirmed, process 1.
DEVICE_99 = (b"\x82\x01\xfe" b"\xb4\x00\x00\x00\x00" b"\xb4\x17\x3b\x3b\x63"
             b"\x0c\x02\x00\x00\x63" b"\x21\x01" b"\x10" b"\x82\x05\xe0")
# The same destination for Device 98.
DEVICE_98 = DEVICE_99.replace(b"\x0c\x02\x00\x00\x63", b"\x0c\x02\x00\x00\x62")
RECIPIENT_LIST = PropertyIdentifier.RECIPIENT_LIST


def stub_method() -> ast.FunctionDef:
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
        if isinstance(node, ast.FunctionDef) and node.name == "add_notification_class"
    )


def class_oid(instance: int) -> ObjectIdentifier:
    return ObjectIdentifier(ObjectType.NOTIFICATION_CLASS, instance)


class NotificationClassRegistrationTests(unittest.TestCase):
    def test_runtime_and_stub_agree(self) -> None:
        runtime = inspect.signature(BACnetServer.add_notification_class).parameters
        self.assertEqual(
            [(name, parameter.kind) for name, parameter in runtime.items() if name != "self"],
            PARAMETERS,
        )
        self.assertEqual(runtime["notification_class"].default, 0)
        self.assertIsNone(runtime["storage_path"].default)
        method = stub_method()
        self.assertEqual(
            [(arg.arg, POSITIONAL) for arg in method.args.args if arg.arg != "self"],
            PARAMETERS,
        )
        self.assertEqual([ast.unparse(default) for default in method.args.defaults], ["0", "None"])

    def test_an_empty_storage_path_is_refused(self) -> None:
        server = BACnetServer(9874)
        with self.assertRaisesRegex(BacnetError, "path must not be empty"):
            server.add_notification_class(1, "Empty path", storage_path="")
        self.assertEqual(server._pending_registration_count(), 0)


class NotificationClassRestartTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name) / "state"
        self.client = BACnetClient(interface="127.0.0.1", port=0)
        await self.client.__aenter__()

        async def stop_client() -> None:
            await self.client.__aexit__(None, None, None)

        self.addAsyncCleanup(stop_client)

    async def start(self) -> BACnetServer:
        """A server with class 1 kept in the state directory and class 2 in memory."""
        server = BACnetServer(9872, interface="127.0.0.1", port=0)
        server.add_notification_class(1, "Kept", 1, str(self.state / "class-1"))
        server.add_notification_class(2, "In memory", notification_class=2)
        await server.start()
        self.address = await server.local_address()
        return server

    async def read(self, instance: int) -> PropertyValue:
        return await asyncio.wait_for(
            self.client.read_property(self.address, class_oid(instance), RECIPIENT_LIST), 3
        )

    async def write(self, instance: int, octets: bytes) -> None:
        await asyncio.wait_for(
            self.client.write_property(
                self.address, class_oid(instance), RECIPIENT_LIST,
                PropertyValue.application_data(octets),
            ),
            3,
        )

    async def test_a_written_recipient_list_survives_a_restart(self) -> None:
        server = await self.start()
        try:
            for instance in (1, 2):
                await self.write(instance, DEVICE_99 + DEVICE_98)
                self.assertEqual(
                    await self.read(instance),
                    PropertyValue.application_data(DEVICE_99 + DEVICE_98),
                )
        finally:
            await server.stop()

        server = await self.start()
        try:
            # The kept class serves the written list; the other starts empty.
            self.assertEqual(
                await self.read(1), PropertyValue.application_data(DEVICE_99 + DEVICE_98)
            )
            self.assertEqual(await self.read(2), PropertyValue.list([]))
        finally:
            await server.stop()

    async def test_a_list_that_cannot_be_saved_is_refused_and_the_old_list_stays(self) -> None:
        server = await self.start()
        try:
            await self.write(1, DEVICE_99)
            # A file where the storage directory belongs makes the next save
            # fail, and the write that needed it is refused.
            (self.state / "class-1").unlink()
            self.state.rmdir()
            self.state.write_bytes(b"")
            with self.assertRaises(BacnetProtocolError) as raised:
                await self.write(1, DEVICE_98)
            self.assertEqual(raised.exception.error_class, ErrorClass.DEVICE.to_raw())
            self.assertEqual(raised.exception.error_code, ErrorCode.OPERATIONAL_PROBLEM.to_raw())
            self.assertEqual(await self.read(1), PropertyValue.application_data(DEVICE_99))
            # Class 2 keeps its list in memory, so the same write succeeds.
            await self.write(2, DEVICE_98)
        finally:
            await server.stop()


if __name__ == "__main__":
    unittest.main()
