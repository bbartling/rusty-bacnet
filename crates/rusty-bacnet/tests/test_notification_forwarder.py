"""The Notification Forwarder registration method (#1225, #1260)."""
import ast
import asyncio
import inspect
import tempfile
import unittest
from pathlib import Path

import rusty_bacnet
from rusty_bacnet import (
    BACnetClient, BACnetServer, BacnetProtocolError, ErrorClass, ErrorCode, ObjectIdentifier,
    ObjectType, PropertyIdentifier, PropertyValue,
)

POSITIONAL = inspect.Parameter.POSITIONAL_OR_KEYWORD
KEYWORD = inspect.Parameter.KEYWORD_ONLY
PARAMETERS = [
    ("instance", POSITIONAL),
    ("name", POSITIONAL),
    ("process_identifier_filter", POSITIONAL),
    ("local_forwarding_only", POSITIONAL),
    ("storage_path", POSITIONAL),
    ("recipients", KEYWORD),
    ("port_filter", KEYWORD),
]

DEVICE_99 = ObjectIdentifier(ObjectType.DEVICE, 99)
B_IP_PEER = bytes([127, 0, 0, 1, 0xBA, 0xC1])
# Device 99, every day, all day, every transition, unconfirmed, process 1.
ALWAYS = {"recipient": {"kind": "device", "object_identifier": DEVICE_99}, "process_identifier": 1}
WEEKDAYS = {
    "recipient": {"kind": "address", "network_number": 0, "mac_address": B_IP_PEER},
    "process_identifier": 300,
    "valid_days": 0b0011111,  # Monday to Friday
    "from_time": (8, 0, 0, 0),
    "to_time": (17, 30, 0, 0),
    "issue_confirmed_notifications": True,
    "transitions": 0b101,  # to-offnormal and to-normal
}
# ALWAYS as a read gives it back, with the defaults filled in.
ALWAYS_READ = {
    **ALWAYS,
    "valid_days": 0x7F,
    "from_time": (0, 0, 0, 0),
    "to_time": (23, 59, 59, 99),
    "issue_confirmed_notifications": False,
    "transitions": 0b111,
}
# Port 0 enabled, port 1 disabled.
PORT_FILTER = [(0, True), (1, False)]
# One Subscribed_Recipients entry: Device 99, process 1, unconfirmed, 60 minutes.
SUBSCRIPTION = b"\x0e\x0c\x02\x00\x00\x63\x0f\x19\x01\x29\x00\x39\x3c"


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
        if isinstance(node, ast.FunctionDef) and node.name == "add_notification_forwarder"
    )


def stub_parameters() -> list[tuple[str, inspect._ParameterKind]]:
    method = stub_method()
    return [
        *((arg.arg, POSITIONAL) for arg in method.args.args if arg.arg != "self"),
        *((arg.arg, KEYWORD) for arg in method.args.kwonlyargs),
    ]


class NotificationForwarderRegistrationTests(unittest.TestCase):
    def test_runtime_and_stub_agree(self) -> None:
        runtime = inspect.signature(BACnetServer.add_notification_forwarder).parameters
        self.assertEqual(
            [(name, parameter.kind) for name, parameter in runtime.items() if name != "self"],
            PARAMETERS,
        )
        self.assertEqual(stub_parameters(), PARAMETERS)
        for name in ("process_identifier_filter", "storage_path", "recipients", "port_filter"):
            self.assertIsNone(runtime[name].default, name)
        self.assertIs(runtime["local_forwarding_only"].default, False)
        self.assertEqual(
            [ast.unparse(default) for default in stub_method().args.kw_defaults],
            ["None", "None"],
        )

    def test_refused_seeds_leave_nothing_pending(self) -> None:
        server = BACnetServer(9873)
        server.add_notification_forwarder(1, "Full", recipients=[ALWAYS] * 32)
        # A 33rd destination is refused as a client's write would be.
        with self.assertRaises(BacnetProtocolError) as raised:
            server.add_notification_forwarder(2, "Past the cap", recipients=[ALWAYS] * 33)
        self.assertEqual(raised.exception.error_class, ErrorClass.RESOURCES.to_raw())
        self.assertEqual(raised.exception.error_code, ErrorCode.NO_SPACE_TO_WRITE_PROPERTY.to_raw())
        long_mac = dict(ALWAYS, recipient={"kind": "address", "network_number": 0,
                                           "mac_address": bytes(19)})
        with self.assertRaises(BacnetProtocolError) as raised:
            server.add_notification_forwarder(2, "Long MAC", recipients=[long_mac])
        self.assertEqual(raised.exception.error_code, ErrorCode.INVALID_DATA_TYPE.to_raw())
        server.add_notification_forwarder(
            3, "Longest MAC",
            recipients=[dict(long_mac, recipient=dict(long_mac["recipient"], mac_address=bytes(18)))])
        # Shapes and Python types are checked before the object is built.
        for recipients, error in (
            (["device"], TypeError),
            ([dict(ALWAYS, days=1)], ValueError),
            ([dict(ALWAYS, valid_days=128)], ValueError),
            ([{"recipient": ALWAYS["recipient"]}], ValueError),
        ):
            with self.subTest(recipients=recipients):
                with self.assertRaises(error):
                    server.add_notification_forwarder(2, "Refused", recipients=recipients)
        for port_filter, error in (([(256, True)], OverflowError), ([(0, 1)], TypeError)):
            with self.subTest(port_filter=port_filter):
                with self.assertRaises(error):
                    server.add_notification_forwarder(2, "Refused", port_filter=port_filter)
        self.assertEqual(server._pending_registration_count(), 2)


class NotificationForwarderServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name) / "state"
        self.server = BACnetServer(9871, interface="127.0.0.1", port=0)
        self.server.add_notification_forwarder(
            1,
            "Forwarder",
            process_identifier_filter=5,
            local_forwarding_only=True,
            storage_path=str(self.state / "forwarder-1"),
        )
        self.server.add_notification_forwarder(2, "Open forwarder")
        self.server.add_notification_forwarder(
            3, "Seeded forwarder", recipients=[ALWAYS, WEEKDAYS], port_filter=PORT_FILTER
        )
        with self.assertRaisesRegex(RuntimeError, "^server not started$"):
            await self.server.forwarder_save_counters()
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

    async def read(self, instance: int, property_id: PropertyIdentifier,
                   index: int | None = None) -> PropertyValue:
        oid = ObjectIdentifier(ObjectType.NOTIFICATION_FORWARDER, instance)
        return await asyncio.wait_for(
            self.client.read_property(self.address, oid, property_id, index), 3
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

    async def test_seeded_recipient_list_and_port_filter_read_back(self) -> None:
        # The lists read back as the values seeded, every key of a
        # destination filled in (#1310); an empty list as [].
        recipients = await self.read(3, PropertyIdentifier.RECIPIENT_LIST)
        self.assertEqual(recipients.tag, "list")
        self.assertEqual(recipients.value, [ALWAYS_READ, WEEKDAYS])
        self.assertEqual(await self.read(2, PropertyIdentifier.RECIPIENT_LIST),
                         PropertyValue.list([]))
        port_filter = PropertyIdentifier.PORT_FILTER
        self.assertEqual((await self.read(3, port_filter)).value, PORT_FILTER)
        self.assertEqual(await self.read(3, port_filter, 0), PropertyValue.unsigned(2))
        self.assertEqual((await self.read(3, port_filter, 2)).value, PORT_FILTER[1])
        # Without port_filter the property is absent.
        with self.assertRaises(BacnetProtocolError) as raised:
            await self.read(2, port_filter)
        self.assertEqual(raised.exception.error_code, ErrorCode.UNKNOWN_PROPERTY.to_raw())

    async def test_a_failed_save_is_counted(self) -> None:
        self.assertEqual(
            await self.server.forwarder_save_counters(),
            {instance: {"failed_saves": 0} for instance in (1, 2, 3)},
        )
        # A file where the storage directory belongs makes the next save fail,
        # and the write that needed it is refused.
        self.state.write_bytes(b"")
        oid = ObjectIdentifier(ObjectType.NOTIFICATION_FORWARDER, 1)
        with self.assertRaises(BacnetProtocolError) as raised:
            await asyncio.wait_for(
                self.client.write_property(
                    self.address, oid, PropertyIdentifier.SUBSCRIBED_RECIPIENTS,
                    PropertyValue.application_data(SUBSCRIPTION),
                ),
                3,
            )
        self.assertEqual(raised.exception.error_class, ErrorClass.DEVICE.to_raw())
        self.assertEqual(raised.exception.error_code, ErrorCode.OPERATIONAL_PROBLEM.to_raw())
        self.assertEqual(
            await self.server.forwarder_save_counters(),
            {1: {"failed_saves": 1}, 2: {"failed_saves": 0}, 3: {"failed_saves": 0}},
        )
        # Forwarder 2 keeps its list in memory, so the same write succeeds.
        await asyncio.wait_for(
            self.client.write_property(
                self.address, ObjectIdentifier(ObjectType.NOTIFICATION_FORWARDER, 2),
                PropertyIdentifier.SUBSCRIBED_RECIPIENTS,
                PropertyValue.application_data(SUBSCRIPTION),
            ),
            3,
        )
        await self.server.stop()
        with self.assertRaisesRegex(RuntimeError, "^server not started$"):
            await self.server.forwarder_save_counters()


if __name__ == "__main__":
    unittest.main()
