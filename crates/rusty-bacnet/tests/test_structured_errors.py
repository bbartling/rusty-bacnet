"""Structured error bodies (#1047): a raw UDP peer answers each request with
the exact Clause 21 error body its service defines, and BacnetProtocolError
carries the fields that body adds. Every field a body lacks stays None."""
import asyncio
import socket
import unittest

from rusty_bacnet import (
    BACnetClient,
    BacnetProtocolError,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

AV7 = ObjectIdentifier(ObjectType.ANALOG_VALUE, 7)
FIELDS = (
    "first_failed_element_number",
    "first_failed_write_attempt",
    "first_failed_subscription",
    "vendor_id",
    "service_number",
    "error_parameters",
    "vt_session_identifiers",
)

# [0] { PROPERTY 2, WRITE_ACCESS_DENIED 40 } then [1] element 2.
CREATE_OBJECT_ERROR = bytes.fromhex("0e910291280f1902")
# [0] { 2, 40 } then [1] { (ANALOG_VALUE, 7), PRESENT_VALUE 85, index 3 }.
WPM_ERROR = bytes.fromhex("0e910291280f1e0c00800007195529031f")
# [1] { [0] (ANALOG_VALUE, 7), [1] { PRESENT_VALUE, index 8 },
#       [2] { PROPERTY 2, NOT_COV_PROPERTY 44 } }.
SCPM_SUBSCRIPTION_ERROR = bytes.fromhex("1e0c008000071e095519081f2e9102912c2f1f")
# [0] { SERVICES 5, VALUE_OUT_OF_RANGE 37 }.
SCPM_GENERAL_ERROR = bytes.fromhex("0e910591250f")
# [0] { SERVICES 5, OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED 45 }, [1] vendor 555,
# [2] service 7, [3] { Unsigned 1 }.
PRIVATE_TRANSFER_ERROR = bytes.fromhex("0e9105912d0f1a022b29073e21013f")
# [0] { SERVICES 5, VT_SESSION_TERMINATION_FAILURE 39 }, [1] { 1, 4 }.
VT_CLOSE_ERROR = bytes.fromhex("0e910591270f1e210121041f")
# [0] { SERVICES 5, UNKNOWN_VT_SESSION 35 }, list omitted.
VT_CLOSE_ERROR_WITHOUT_LIST = bytes.fromhex("0e910591230f")


class StructuredErrorTests(unittest.IsolatedAsyncioTestCase):
    async def raised(self, peer, operation, body):
        """Answer the request `operation` sends with an Error PDU carrying
        `body`, and return the BacnetProtocolError it raises."""
        loop = asyncio.get_running_loop()
        packet, sender = await asyncio.wait_for(loop.sock_recvfrom(peer, 2048), 2)
        npdu = b"\x01\x00" + bytes((0x50, packet[8], packet[9])) + body
        await loop.sock_sendto(peer, b"\x81\x0a" + (4 + len(npdu)).to_bytes(2, "big") + npdu, sender)
        with self.assertRaises(BacnetProtocolError) as raised:
            await asyncio.wait_for(operation, 2)
        return raised.exception

    def assert_only(self, error, class_, code, **fields):
        self.assertEqual((error.error_class, error.error_code), (class_, code))
        for name in FIELDS:
            self.assertEqual(getattr(error, name), fields.get(name), name)

    async def test_each_structured_body_reaches_python(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            async with BACnetClient(interface="127.0.0.1", port=0) as client:
                error = await self.raised(
                    peer,
                    client.create_object(
                        address,
                        ObjectType.ANALOG_VALUE,
                        [
                            (PropertyIdentifier.PRESENT_VALUE, PropertyValue.real(1.0), None, None),
                            (PropertyIdentifier.DESCRIPTION, PropertyValue.character_string("d"), None, None),
                        ],
                    ),
                    CREATE_OBJECT_ERROR,
                )
                self.assert_only(error, 2, 40, first_failed_element_number=2)

                error = await self.raised(
                    peer,
                    client.write_property_multiple(
                        address, [(AV7, [(PropertyIdentifier.PRESENT_VALUE, PropertyValue.real(1.0), None, 3)])]
                    ),
                    WPM_ERROR,
                )
                self.assert_only(
                    error,
                    2,
                    40,
                    first_failed_write_attempt={
                        "object_identifier": AV7,
                        "property_identifier": PropertyIdentifier.PRESENT_VALUE,
                        "property_array_index": 3,
                    },
                )

                subscribe = lambda: client.subscribe_cov_property_multiple(  # noqa: E731
                    address,
                    1,
                    [(AV7, [(PropertyIdentifier.PRESENT_VALUE, 8, None, False)])],
                    False,
                    max_notification_delay=10,
                    lifetime=300,
                )
                error = await self.raised(peer, subscribe(), SCPM_SUBSCRIPTION_ERROR)
                self.assert_only(
                    error,
                    2,
                    44,
                    first_failed_subscription={
                        "object_identifier": AV7,
                        "property_identifier": PropertyIdentifier.PRESENT_VALUE,
                        "property_array_index": 8,
                    },
                )
                error = await self.raised(peer, subscribe(), SCPM_GENERAL_ERROR)
                self.assert_only(error, 5, 37)

                error = await self.raised(
                    peer, client.confirmed_private_transfer(address, 555, 7), PRIVATE_TRANSFER_ERROR
                )
                self.assert_only(error, 5, 45, vendor_id=555, service_number=7, error_parameters=b"\x21\x01")

                error = await self.raised(peer, client.vt_close(address, [10, 11]), VT_CLOSE_ERROR)
                self.assert_only(error, 5, 39, vt_session_identifiers=[1, 4])
                error = await self.raised(peer, client.vt_close(address, [10]), VT_CLOSE_ERROR_WITHOUT_LIST)
                self.assert_only(error, 5, 35)

                # A device answering with only the class and code fills none.
                error = await self.raised(
                    peer, client.create_object(address, ObjectType.ANALOG_VALUE), b"\x91\x01\x91\x24"
                )
                self.assert_only(error, 1, 36)

    def test_fields_default_to_none_on_the_class(self):
        error = BacnetProtocolError("raised by hand")
        for name in FIELDS:
            self.assertIsNone(getattr(error, name), name)


if __name__ == "__main__":
    unittest.main()
