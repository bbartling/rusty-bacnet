"""Installed WP/WPM absent-property errors and retained successful prefixes."""
import asyncio
import unittest

from rusty_bacnet import (
    BACnetClient, BACnetServer, BacnetProtocolError, ErrorClass, ErrorCode,
    ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
)


class UnknownPropertyWriteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = BACnetServer(9870, interface="127.0.0.1", port=0)
        self.server.add_analog_input(1, "AI")
        self.server.add_schedule(1, "Schedule")
        await self.server.start()
        async def stop_server():
            await self.server.stop()
        self.addAsyncCleanup(stop_server)
        self.address = await self.server.local_address()
        self.client = BACnetClient(interface="127.0.0.1", port=0)
        await self.client.__aenter__()
        async def stop_client():
            await self.client.__aexit__(None, None, None)
        self.addAsyncCleanup(stop_client)

    async def test_wp_absent_vs_read_only_for_null_and_ordinary_values(self):
        for kind in (ObjectType.ANALOG_INPUT, ObjectType.SCHEDULE):
            oid = ObjectIdentifier(kind, 1)
            for value in (PropertyValue.null(), PropertyValue.unsigned(17)):
                for property_id, expected in (
                    (PropertyIdentifier.from_raw(5555), ErrorCode.UNKNOWN_PROPERTY),
                    (PropertyIdentifier.OBJECT_IDENTIFIER, ErrorCode.WRITE_ACCESS_DENIED),
                ):
                    with self.subTest(kind=kind, value=value, property_id=property_id):
                        with self.assertRaises(BacnetProtocolError) as caught:
                            await asyncio.wait_for(self.client.write_property(
                                self.address, oid, property_id, value
                            ), 3)
                        self.assertEqual(caught.exception.error_class, ErrorClass.PROPERTY.to_raw())
                        self.assertEqual(caught.exception.error_code, expected.to_raw())

    async def test_wpm_error_preserves_description_prefix(self):
        for kind in (ObjectType.ANALOG_INPUT, ObjectType.SCHEDULE):
            oid = ObjectIdentifier(kind, 1)
            for value in (PropertyValue.null(), PropertyValue.unsigned(17)):
                for property_id, expected in (
                    (PropertyIdentifier.from_raw(5555), ErrorCode.UNKNOWN_PROPERTY),
                    (PropertyIdentifier.OBJECT_IDENTIFIER, ErrorCode.WRITE_ACCESS_DENIED),
                ):
                    with self.subTest(kind=kind, value=value, property_id=property_id):
                        prefix = PropertyValue.character_string(f"prefix-{kind}-{value}-{property_id}")
                        request = [(oid, [
                            (PropertyIdentifier.DESCRIPTION, prefix, None, None),
                            (property_id, value, None, None),
                            (PropertyIdentifier.DESCRIPTION, PropertyValue.character_string("unreached"), None, None),
                        ])]
                        with self.assertRaises(BacnetProtocolError) as caught:
                            await asyncio.wait_for(self.client.write_property_multiple(self.address, request), 3)
                        self.assertEqual(caught.exception.error_class, ErrorClass.PROPERTY.to_raw())
                        self.assertEqual(caught.exception.error_code, expected.to_raw())
                        self.assertEqual(await self.client.read_property(
                            self.address, oid, PropertyIdentifier.DESCRIPTION
                        ), prefix)
