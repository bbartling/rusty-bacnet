"""Endpoint Groups and the server role's read work limit (#1250).

The installed extension: constructor validation for all three owners, Group
registration, and a real B/IP Group read over the limit, which the endpoint
answers with an Abort (OUT_OF_RESOURCES).
"""

from __future__ import annotations

import asyncio
import inspect
import struct
import unittest
from pathlib import Path
from typing import Any

import rusty_bacnet
from rusty_bacnet import (
    BACnetClient,
    BacnetAbortError,
    BipEndpoint,
    MstpEndpoint,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    ScEndpoint,
)

OUT_OF_RESOURCES = 9
PV = PropertyIdentifier.PRESENT_VALUE
AI_1 = ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)

# No I/O happens in a constructor, so placeholder addresses and paths serve.
OWNERS: list[tuple[type, dict[str, Any]]] = [
    (BipEndpoint, {"port": 0}),
    (
        ScEndpoint,
        {
            "sc_hub": "wss://localhost:1",
            "sc_vmac": b"\x02\x00\x00\x00\x00\x01",
            "sc_ca_cert": "ca.pem",
            "sc_client_cert": "cert.pem",
            "sc_client_key": "key.pem",
            "sc_device_uuid": bytes.fromhex("8e62ac46d7084226913776a32b619315"),
        },
    ),
    (MstpEndpoint, {"serial_port": "/tmp/nonexistent"}),
]


class ReadWorkLimitConstructorTests(unittest.TestCase):
    def test_default_keyword_only_stub_and_range(self):
        stub = Path(rusty_bacnet.__file__).with_suffix(".pyi").read_text(encoding="utf-8")
        self.assertEqual(stub.count("read_work_limit: int = 256"), len(OWNERS))
        native_max = (1 << (8 * struct.calcsize("P"))) - 1
        for cls, args in OWNERS:
            with self.subTest(owner=cls.__name__):
                parameter = inspect.signature(cls).parameters["read_work_limit"]
                self.assertEqual(parameter.default, 256)
                self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
                for value, error in [
                    (0, ValueError),
                    (-1, OverflowError),
                    (1 << 200, OverflowError),
                    (1.5, TypeError),
                ]:
                    with self.subTest(owner=cls.__name__, value=value):
                        with self.assertRaises(error):
                            cls(123, **args, read_work_limit=value)
                with self.assertRaisesRegex(ValueError, "read_work_limit"):
                    cls(123, **args, read_work_limit=0)
                # The limit is a count, never an allocation size.
                cls(123, **args, read_work_limit=native_max)


class EndpointGroupRegistrationTests(unittest.TestCase):
    def test_members_are_validated_when_added(self):
        group_1 = ObjectIdentifier(ObjectType.GROUP, 1)
        for cls, args in OWNERS:
            with self.subTest(owner=cls.__name__):
                endpoint = cls(123, **args)
                endpoint.add_group(1, "Empty")
                endpoint.add_group(2, "Members", [(AI_1, [(PV, None)]), (group_1, [(PropertyIdentifier.OBJECT_NAME, None)])])
                self.assertEqual(endpoint._pending_registration_count(), 2)
                # Each refusal names the member's position and the rule it breaks.
                for members, message in (
                    ([(AI_1, [])], r"^group member 0: the member lists no properties$"),
                    ([(group_1, [(PV, None)])], r"^group member 0: the member reports a Group"),
                    ([(group_1, [(PropertyIdentifier.ALL, None)])], r"^group member 0: the member reports a Group"),
                ):
                    with self.subTest(owner=cls.__name__, members=members):
                        with self.assertRaisesRegex(ValueError, message):
                            endpoint.add_group(3, "Refused", members)
                # Any property identifier, those ASHRAE assigns past 4194303
                # included (#887), and any unsigned32 index, are accepted.
                wide_identifiers = [
                    (PropertyIdentifier.from_raw(raw), 0)
                    for raw in (4_194_303, 4_194_304, (1 << 32) - 1)
                ]
                endpoint.add_group(
                    4,
                    "Edges",
                    [(AI_1, [*wide_identifiers, (PropertyIdentifier.DEFAULT_COLOR, None), (PV, (1 << 32) - 1)])],
                )
                # Indexes outside unsigned32 fail conversion, as for read_property_multiple specs.
                for index in (-1, 1 << 32):
                    with self.subTest(owner=cls.__name__, index=index):
                        with self.assertRaises(OverflowError):
                            endpoint.add_group(3, "Refused", [(AI_1, [(PV, index)])])
                with self.assertRaises(TypeError):
                    endpoint.add_group(3, "Malformed", [AI_1])
                self.assertEqual(endpoint._pending_registration_count(), 3)


class ReadWorkLimitWireTests(unittest.IsolatedAsyncioTestCase):
    async def read_groups(self, **limit: int) -> list[int | None]:
        """Reads Group 1 (three rows) then Group 2 (two rows) from a B/IP
        endpoint; each result is None when served, else the abort reason."""
        endpoint = BipEndpoint(
            device_instance=9201,
            interface="127.0.0.1",
            broadcast_address="127.255.255.255",
            port=0,
            **limit,
        )
        endpoint.add_analog_input(1, "AI-1", present_value=21.5)
        endpoint.add_group(1, "Three rows", [(AI_1, [(PV, None), (PropertyIdentifier.OBJECT_NAME, None)])])
        endpoint.add_group(2, "Two rows", [(AI_1, [(PV, None)])])
        results: list[int | None] = []
        async with endpoint:
            address = await endpoint.local_address()
            async with BACnetClient(interface="127.0.0.1", port=0, apdu_timeout_ms=2000) as client:
                for instance in (1, 2):
                    group = ObjectIdentifier(ObjectType.GROUP, instance)
                    try:
                        async with asyncio.timeout(5):
                            await client.read_property(address, group, PV)
                        results.append(None)
                    except BacnetAbortError as error:
                        results.append(error.reason)
        return results

    async def test_group_read_over_the_limit_aborts_out_of_resources(self):
        self.assertEqual(await self.read_groups(read_work_limit=2), [OUT_OF_RESOURCES, None])
        # The default, 256, serves both.
        self.assertEqual(await self.read_groups(), [None, None])


if __name__ == "__main__":
    unittest.main()
