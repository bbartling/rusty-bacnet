"""An Object_Name another object holds is PROPERTY / DUPLICATE_NAME (#1434).

The WriteProperty and WritePropertyMultiple error tables (Clauses 15.9.1.3.1
and 15.10.1.3.1) pair the code with the PROPERTY class, as Clause 18.3 files
it. A local write, a network write and a CreateObject initial value all answer
with that pair, and nothing is renamed or created."""
import asyncio
import unittest

from rusty_bacnet import (
    BACnetClient, BACnetServer, BacnetProtocolError, ErrorClass, ErrorCode,
    ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
)

AI = ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)
NAME = PropertyIdentifier.OBJECT_NAME
TAKEN = PropertyValue.character_string("BV")


class DuplicateNameTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = BACnetServer(9871, interface="127.0.0.1", port=0)
        self.server.add_analog_input(1, "AI")
        self.server.add_binary_value(1, "BV")
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

    async def refused(self, operation):
        with self.assertRaises(BacnetProtocolError) as caught:
            await asyncio.wait_for(operation, 3)
        error = caught.exception
        self.assertEqual(
            (error.error_class, error.error_code),
            (ErrorClass.PROPERTY.to_raw(), ErrorCode.DUPLICATE_NAME.to_raw()),
        )
        return error

    async def assert_unchanged(self):
        name = await self.server.read_property(AI, NAME)
        self.assertEqual(name, PropertyValue.character_string("AI"))

    async def test_write_property_local(self):
        await self.refused(
            self.server.write_property_local(AI, NAME, TAKEN, source_object=None)
        )
        await self.assert_unchanged()

    async def test_write_property_and_write_property_multiple(self):
        await self.refused(self.client.write_property(self.address, AI, NAME, TAKEN))
        error = await self.refused(
            self.client.write_property_multiple(
                self.address, [(AI, [(NAME, TAKEN, None, None)])]
            )
        )
        self.assertEqual(
            error.first_failed_write_attempt,
            {
                "object_identifier": AI,
                "property_identifier": NAME,
                "property_array_index": None,
            },
        )
        await self.assert_unchanged()

    async def test_create_object_names_the_initial_value(self):
        error = await self.refused(
            self.client.create_object(
                self.address,
                ObjectType.BINARY_VALUE,
                [
                    (PropertyIdentifier.DESCRIPTION, PropertyValue.character_string("d"), None, None),
                    (NAME, PropertyValue.character_string("AI"), None, None),
                ],
            )
        )
        self.assertEqual(error.first_failed_element_number, 2)
        with self.assertRaises(BacnetProtocolError):
            await self.server.read_property(ObjectIdentifier(ObjectType.BINARY_VALUE, 2), NAME)


if __name__ == "__main__":
    unittest.main()
