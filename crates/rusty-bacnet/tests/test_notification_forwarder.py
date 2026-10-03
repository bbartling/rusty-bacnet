"""The Notification Forwarder registration method (#1225)."""
import ast
import asyncio
import inspect
import tempfile
import unittest
from pathlib import Path

import rusty_bacnet
from rusty_bacnet import (
    BACnetClient, BACnetServer, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
)

PARAMETERS = [
    "self",
    "instance",
    "name",
    "process_identifier_filter",
    "local_forwarding_only",
    "storage_path",
]


def stub_parameters() -> list[str]:
    stub_path = Path(rusty_bacnet.__file__).with_suffix(".pyi")
    tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    server = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "BACnetServer"
    )
    method = next(
        node
        for node in server.body
        if isinstance(node, ast.FunctionDef) and node.name == "add_notification_forwarder"
    )
    return [arg.arg for arg in [*method.args.posonlyargs, *method.args.args]]


class NotificationForwarderRegistrationTests(unittest.TestCase):
    def test_runtime_and_stub_agree(self) -> None:
        runtime = inspect.signature(BACnetServer.add_notification_forwarder).parameters
        self.assertEqual(list(runtime), PARAMETERS)
        self.assertEqual(stub_parameters(), PARAMETERS)
        self.assertIsNone(runtime["process_identifier_filter"].default)
        self.assertIs(runtime["local_forwarding_only"].default, False)
        self.assertIsNone(runtime["storage_path"].default)


class NotificationForwarderServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.server = BACnetServer(9871, interface="127.0.0.1", port=0)
        self.server.add_notification_forwarder(
            1,
            "Forwarder",
            process_identifier_filter=5,
            local_forwarding_only=True,
            storage_path=str(Path(directory.name) / "forwarder-1"),
        )
        self.server.add_notification_forwarder(2, "Open forwarder")
        await self.server.start()

        async def stop_server() -> None:
            await self.server.stop()

        self.addAsyncCleanup(stop_server)
        self.address = await self.server.local_address()
        self.client = BACnetClient(interface="127.0.0.1", port=0)
        await self.client.__aenter__()

        async def stop_client() -> None:
            await self.client.__aexit__(None, None, None)

        self.addAsyncCleanup(stop_client)

    async def read(self, instance: int, property_id: PropertyIdentifier) -> PropertyValue:
        oid = ObjectIdentifier(ObjectType.NOTIFICATION_FORWARDER, instance)
        return await asyncio.wait_for(
            self.client.read_property(self.address, oid, property_id), 3
        )

    async def test_configured_rows_read_back(self) -> None:
        self.assertEqual(
            await self.read(1, PropertyIdentifier.PROCESS_IDENTIFIER_FILTER),
            PropertyValue.unsigned(5),
        )
        self.assertEqual(
            await self.read(1, PropertyIdentifier.LOCAL_FORWARDING_ONLY),
            PropertyValue.boolean(True),
        )
        self.assertEqual(
            await self.read(2, PropertyIdentifier.PROCESS_IDENTIFIER_FILTER),
            PropertyValue.null(),
        )
        self.assertEqual(
            await self.read(2, PropertyIdentifier.LOCAL_FORWARDING_ONLY),
            PropertyValue.boolean(False),
        )


if __name__ == "__main__":
    unittest.main()
