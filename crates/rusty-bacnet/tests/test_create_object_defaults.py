"""What CreateObject gives a new object when the request leaves it out, and
what it may set that WriteProperty can't (#1437, #1429).

A new object's name is the type and instance, or the first free name with a
" (n)" suffix after it when another object holds that. Units on an Analog
Input or Output, and Number_Of_States and State_Text written whole on a
multi-state object, take a CreateObject initial value but stay
WRITE_ACCESS_DENIED to WriteProperty. Number_Of_States applies first, so the
order of the initial values doesn't change the object."""
import asyncio
import unittest

from rusty_bacnet import (
    BACnetClient, BACnetServer, BacnetProtocolError, ErrorClass, ErrorCode,
    ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
)

AI = ObjectType.ANALOG_INPUT
MSV = ObjectType.MULTI_STATE_VALUE
BV = ObjectType.BINARY_VALUE
NAME = PropertyIdentifier.OBJECT_NAME
UNITS = PropertyIdentifier.UNITS
STATES = PropertyIdentifier.NUMBER_OF_STATES
STATE_TEXT = PropertyIdentifier.STATE_TEXT
CELSIUS = PropertyValue.enumerated(62)
LABELS = PropertyValue.list(
    [PropertyValue.character_string(label) for label in ("Off", "Low", "High")]
)


def initial(property_id, value):
    return (property_id, value, None, None)


class CreateObjectDefaultsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server = BACnetServer(9872, interface="127.0.0.1", port=0)
        self.server.add_analog_input(1, "AI", units=95)
        # Holds the name the next Binary Value would be given.
        self.server.add_binary_input(1, "BINARY_VALUE-1")
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

    async def create(self, specifier, values):
        await asyncio.wait_for(
            self.client.create_object(self.address, specifier, values), 3
        )

    async def read(self, oid, property_id):
        return await self.server.read_property(oid, property_id)

    async def refused(self, operation, code, element=None):
        with self.assertRaises(BacnetProtocolError) as caught:
            await asyncio.wait_for(operation, 3)
        error = caught.exception
        self.assertEqual(
            (error.error_class, error.error_code),
            (ErrorClass.PROPERTY.to_raw(), code.to_raw()),
        )
        self.assertEqual(error.first_failed_element_number, element)

    async def test_a_taken_default_name_takes_a_suffix_or_the_requested_name(self):
        await self.create(BV, [])
        first = ObjectIdentifier(BV, 1)
        self.assertEqual(
            await self.read(first, NAME),
            PropertyValue.character_string("BINARY_VALUE-1 (2)"),
        )
        await self.create(ObjectIdentifier(BV, 5), [])
        await self.create(BV, [initial(NAME, PropertyValue.character_string("Fan"))])
        second = ObjectIdentifier(BV, 2)
        self.assertEqual(
            await self.read(second, NAME), PropertyValue.character_string("Fan")
        )

    async def test_units_round_trip_and_stay_read_only(self):
        await self.create(AI, [initial(UNITS, CELSIUS)])
        created = ObjectIdentifier(AI, 2)
        self.assertEqual(await self.read(created, UNITS), CELSIUS)
        await self.refused(
            self.client.write_property(
                self.address, created, UNITS, PropertyValue.enumerated(98)
            ),
            ErrorCode.WRITE_ACCESS_DENIED,
        )
        self.assertEqual(await self.read(created, UNITS), CELSIUS)

    async def test_states_round_trip_in_either_order(self):
        count = PropertyValue.unsigned(3)
        await self.create(MSV, [initial(STATES, count), initial(STATE_TEXT, LABELS)])
        await self.create(MSV, [initial(STATE_TEXT, LABELS), initial(STATES, count)])
        for instance in (1, 2):
            created = ObjectIdentifier(MSV, instance)
            self.assertEqual(await self.read(created, STATES), count)
            self.assertEqual(await self.read(created, STATE_TEXT), LABELS)
        await self.refused(
            self.client.write_property(
                self.address, ObjectIdentifier(MSV, 1), STATE_TEXT, LABELS
            ),
            ErrorCode.WRITE_ACCESS_DENIED,
        )

    async def test_a_state_text_of_the_wrong_length_is_refused(self):
        await self.refused(
            self.create(
                MSV,
                [
                    initial(PropertyIdentifier.DESCRIPTION, PropertyValue.character_string("d")),
                    initial(STATE_TEXT, LABELS),
                    initial(STATES, PropertyValue.unsigned(4)),
                ],
            ),
            ErrorCode.VALUE_OUT_OF_RANGE,
            element=2,
        )
        with self.assertRaises(BacnetProtocolError):
            await self.read(ObjectIdentifier(MSV, 1), NAME)


if __name__ == "__main__":
    unittest.main()
