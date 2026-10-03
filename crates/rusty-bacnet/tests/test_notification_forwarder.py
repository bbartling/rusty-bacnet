"""The Notification Forwarder registration method (#1225, #1260)."""
import ast
import asyncio
import inspect
import socket
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
# The same two destinations as Recipient_List serves them.
ALWAYS_OCTETS = (b"\x82\x01\xfe" b"\xb4\x00\x00\x00\x00" b"\xb4\x17\x3b\x3b\x63"
                 b"\x0c\x02\x00\x00\x63" b"\x21\x01" b"\x10" b"\x82\x05\xe0")
WEEKDAYS_OCTETS = (b"\x82\x01\xf8" b"\xb4\x08\x00\x00\x00" b"\xb4\x11\x1e\x00\x00"
                   b"\x1e\x21\x00\x65\x06\x7f\x00\x00\x01\xba\xc1\x1f"
                   b"\x22\x01\x2c" b"\x11" b"\x82\x05\xa0")
# Port 0 enabled, port 1 disabled: each element is port-id [0], enabled [1].
PORT_FILTER = [(0, True), (1, False)]
PORT_0_ENABLED = b"\x09\x00\x19\x01"
PORT_1_DISABLED = b"\x09\x01\x19\x00"
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


def unsigned(tag: int, value: int) -> bytes:
    """A context-tagged Unsigned."""
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return bytes([(tag << 4) | 0x08 | len(body)]) + body


async def read_octets(sock: socket.socket, address: str, oid: ObjectIdentifier,
                      prop: PropertyIdentifier, index: int | None = None) -> bytes:
    """ReadProperty over B/IP from a raw socket; returns the value octets
    between the ACK's opening and closing tag 3. BACnetClient decodes only a
    value's first element, so a list is read this way."""
    request = (bytes([0x0C]) + ((oid.object_type.to_raw() << 22) | oid.instance).to_bytes(4, "big")
               + unsigned(1, prop.to_raw())
               + (b"" if index is None else unsigned(2, index)))
    npdu = b"\x01\x04" + bytes([0x00, 0x05, 1, 0x0C]) + request
    ip, port = address.rsplit(":", 1)
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, b"\x81\x0a" + (len(npdu) + 4).to_bytes(2, "big") + npdu,
                           (ip, int(port)))
    reply, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), 3)
    header = bytes([0x30, 1, 0x0C]) + request + b"\x3e"
    ack = reply[6:]  # BVLL, then an NPDU with no routing fields
    assert ack.startswith(header) and ack.endswith(b"\x3f"), ack.hex()
    return ack[len(header):-1]


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
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.sock.close)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)

    async def read(self, instance: int, property_id: PropertyIdentifier) -> PropertyValue:
        oid = ObjectIdentifier(ObjectType.NOTIFICATION_FORWARDER, instance)
        return await asyncio.wait_for(
            self.client.read_property(self.address, oid, property_id), 3
        )

    async def octets(self, instance: int, property_id: PropertyIdentifier,
                     index: int | None = None) -> bytes:
        oid = ObjectIdentifier(ObjectType.NOTIFICATION_FORWARDER, instance)
        return await read_octets(self.sock, self.address, oid, property_id, index)

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
        self.assertEqual(
            await self.octets(3, PropertyIdentifier.RECIPIENT_LIST),
            ALWAYS_OCTETS + WEEKDAYS_OCTETS,
        )
        self.assertEqual(await self.octets(2, PropertyIdentifier.RECIPIENT_LIST), b"")
        port_filter = PropertyIdentifier.PORT_FILTER
        self.assertEqual(await self.octets(3, port_filter), PORT_0_ENABLED + PORT_1_DISABLED)
        self.assertEqual(await self.octets(3, port_filter, 0), b"\x21\x02")
        self.assertEqual(await self.octets(3, port_filter, 2), PORT_1_DISABLED)
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
