"""A Notification Class's Recipient_List kept across a restart (#1315), and
seeded from add_notification_class(recipients=...) (#1364)."""
import ast
import asyncio
import inspect
import tempfile
import unittest
from pathlib import Path
from typing import Any

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
    ("recipients", inspect.Parameter.KEYWORD_ONLY),
]

# One destination: Device 99, every day, all day, every transition,
# unconfirmed, process 1.
DEVICE_99 = (b"\x82\x01\xfe" b"\xb4\x00\x00\x00\x00" b"\xb4\x17\x3b\x3b\x63"
             b"\x0c\x02\x00\x00\x63" b"\x21\x01" b"\x10" b"\x82\x05\xe0")
# The same destination for Device 98.
DEVICE_98 = DEVICE_99.replace(b"\x0c\x02\x00\x00\x63", b"\x0c\x02\x00\x00\x62")
RECIPIENT_LIST = PropertyIdentifier.RECIPIENT_LIST


def destination_read(device_instance: int) -> dict[str, Any]:
    """How a read gives back the destination for `device_instance` above."""
    return {
        "recipient": {"kind": "device",
                      "object_identifier": ObjectIdentifier(ObjectType.DEVICE, device_instance)},
        "process_identifier": 1,
        "valid_days": 0x7F,
        "from_time": (0, 0, 0, 0),
        "to_time": (23, 59, 59, 99),
        "issue_confirmed_notifications": False,
        "transitions": 0b111,
    }


def seed(device_instance: int) -> dict[str, Any]:
    """The seed for `device_instance`'s destination: the keys a read gives
    back by default left out."""
    return {"recipient": destination_read(device_instance)["recipient"], "process_identifier": 1}


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
        self.assertIsNone(runtime["recipients"].default)
        method = stub_method()
        self.assertEqual(
            [(arg.arg, POSITIONAL) for arg in method.args.args if arg.arg != "self"]
            + [(arg.arg, inspect.Parameter.KEYWORD_ONLY) for arg in method.args.kwonlyargs],
            PARAMETERS,
        )
        self.assertEqual([ast.unparse(default) for default in method.args.defaults], ["0", "None"])
        self.assertEqual([ast.unparse(default) for default in method.args.kw_defaults], ["None"])

    def test_refused_seeds_leave_nothing_pending(self) -> None:
        server = BACnetServer(9877)
        server.add_notification_class(1, "Full", recipients=[seed(99)] * 32)
        # A 33rd destination is refused as a client's write would be.
        with self.assertRaises(BacnetProtocolError) as raised:
            server.add_notification_class(2, "Past the cap", recipients=[seed(99)] * 33)
        self.assertEqual(raised.exception.error_class, ErrorClass.RESOURCES.to_raw())
        self.assertEqual(raised.exception.error_code, ErrorCode.NO_SPACE_TO_WRITE_PROPERTY.to_raw())
        long_mac = dict(seed(99), recipient={"kind": "address", "network_number": 0,
                                             "mac_address": bytes(19)})
        with self.assertRaises(BacnetProtocolError) as raised:
            server.add_notification_class(2, "Long MAC", recipients=[long_mac])
        self.assertEqual(raised.exception.error_code, ErrorCode.INVALID_DATA_TYPE.to_raw())
        for recipients, error in (
            (["device"], TypeError),
            ([dict(seed(99), days=1)], ValueError),
            ([{"recipient": seed(99)["recipient"]}], ValueError),
        ):
            with self.subTest(recipients=recipients), self.assertRaises(error):
                server.add_notification_class(2, "Refused", recipients=recipients)
        self.assertEqual(server._pending_registration_count(), 1)

    def test_an_empty_storage_path_is_refused(self) -> None:
        server = BACnetServer(9874)
        with self.assertRaisesRegex(BacnetError, "path must not be empty"):
            server.add_notification_class(1, "Empty path", storage_path="")
        self.assertEqual(server._pending_registration_count(), 0)

    def test_storage_path_is_a_str_naming_a_file_this_backend_wrote(self) -> None:
        server = BACnetServer(9875)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "class-1"
            with self.assertRaises(TypeError):
                server.add_notification_class(1, "Path object", storage_path=path)
            path.write_bytes(b"not a notification class file")
            with self.assertRaisesRegex(BacnetError, "has no valid header"):
                server.add_notification_class(1, "Corrupt file", storage_path=str(path))
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

    async def start(self, recipients: list[dict[str, Any]] | None = None) -> BACnetServer:
        """A server with class 1 kept in the state directory and class 2 in
        memory, both seeded with `recipients`."""
        server = BACnetServer(9872, interface="127.0.0.1", port=0)
        server.add_notification_class(1, "Kept", 1, str(self.state / "class-1"),
                                      recipients=recipients)
        server.add_notification_class(2, "In memory", notification_class=2,
                                      recipients=recipients)
        await server.start()
        self.address = await server.local_address()
        return server

    async def read(self, instance: int) -> list[dict[str, Any]]:
        """The destinations a class serves, as a read gives them back."""
        value = await asyncio.wait_for(
            self.client.read_property(self.address, class_oid(instance), RECIPIENT_LIST), 3
        )
        self.assertEqual(value.tag, "list")
        return value.value

    async def write(self, instance: int, octets: bytes) -> None:
        await asyncio.wait_for(
            self.client.write_property(
                self.address, class_oid(instance), RECIPIENT_LIST,
                PropertyValue.application_data(octets),
            ),
            3,
        )

    async def test_a_written_recipient_list_survives_a_restart(self) -> None:
        written = [destination_read(99), destination_read(98)]
        server = await self.start()
        try:
            for instance in (1, 2):
                await self.write(instance, DEVICE_99 + DEVICE_98)
                self.assertEqual(await self.read(instance), written)
        finally:
            await server.stop()

        server = await self.start()
        try:
            # The kept class serves the written list; the other starts empty.
            self.assertEqual(await self.read(1), written)
            self.assertEqual(await self.read(2), [])
        finally:
            await server.stop()

        # Class 1's file names class 1, so another class can't share it.
        other = BACnetServer(9876)
        with self.assertRaisesRegex(BacnetError, "belongs to another object"):
            other.add_notification_class(3, "Shares a path", 3, str(self.state / "class-1"))

    async def test_a_seeded_class_serves_the_seed_until_a_saved_write(self) -> None:
        server = await self.start(recipients=[seed(98)])
        try:
            for instance in (1, 2):
                self.assertEqual(await self.read(instance), [destination_read(98)])
            # A client's write replaces the seed; class 1 saves it.
            for instance in (1, 2):
                await self.write(instance, DEVICE_99)
                self.assertEqual(await self.read(instance), [destination_read(99)])
        finally:
            await server.stop()

        # Restarted with the same seed: the saved list wins on class 1, and
        # class 2, which saved nothing, serves the seed again.
        server = await self.start(recipients=[seed(98)])
        try:
            self.assertEqual(await self.read(1), [destination_read(99)])
            self.assertEqual(await self.read(2), [destination_read(98)])
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
            self.assertEqual(await self.read(1), [destination_read(99)])
            # Class 2 keeps its list in memory, so the same write succeeds.
            await self.write(2, DEVICE_98)
        finally:
            await server.stop()


if __name__ == "__main__":
    unittest.main()
