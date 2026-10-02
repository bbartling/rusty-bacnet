"""Installed Add/RemoveListElement structural preflight and independent wire vectors."""
import asyncio
import socket
import unittest

from rusty_bacnet import BACnetClient, BacnetProtocolError, ObjectIdentifier, ObjectType, PropertyIdentifier

OID = ObjectIdentifier(ObjectType.NOTIFICATION_CLASS, 1)
PID = PropertyIdentifier.from_raw(600)


def invalid_requests():
    yield b"", None
    yield b"\x00", 0
    for body in (b"\x21\x07\x22\x01", b"\x0e\x1f", b"\x0e", b"\x3f", b"\xf9", b"\x65", b"\x0e" * 32 + b"\x0f" * 32):
        yield body, None


def calls(client, body, index, address="invalid-address"):
    return (
        lambda: client.add_list_element(address, OID, PID, body, array_index=index),
        lambda: client.remove_list_element(address, OID, PID, body, array_index=index),
    )


class ListValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_requests_synchronously_before_start_or_address(self):
        client = BACnetClient(interface="127.0.0.1", port=0)
        for body, index in invalid_requests():
            for method, call in enumerate(calls(client, body, index)):
                with self.subTest(body=body.hex(), index=index, method=method):
                    with self.assertRaises(ValueError):
                        call()
        for index in (-1, 1 << 32):
            for call in calls(client, b"\x00", index):
                with self.assertRaises(OverflowError):
                    call()

    async def test_invalid_requests_send_no_prefix(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            async with BACnetClient(interface="127.0.0.1", port=0) as client:
                for body, index in invalid_requests():
                    for call in calls(client, body, index, address):
                        with self.assertRaises(ValueError):
                            call()
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(asyncio.get_running_loop().sock_recvfrom(peer, 2048), .1)

    async def test_both_services_preserve_structural_values_and_exact_wire(self):
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            async with BACnetClient(interface="127.0.0.1", port=0) as client:
                for body in (b"\x60", b"\x10\x11\x21\x07", b"\xf8\xfe", b"\x0e\x1e\x08\x1f\x0f", b"\xd1\x00", b"\x0e" * 31 + b"\x0f" * 31):
                    for index, encoded_index in ((None, b""), (1, b"\x29\x01"), ((1 << 32) - 1, b"\x2c\xff\xff\xff\xff")):
                        for service, call in zip((8, 9), calls(client, body, index, address)):
                            with self.subTest(body=body.hex(), index=index, service=service):
                                operation = call()
                                packet, sender = await asyncio.wait_for(loop.sock_recvfrom(peer, 2048), 2)
                                self.assertEqual(packet[:2], b"\x81\x0a")
                                self.assertEqual(packet[4:6], b"\x01\x04")
                                self.assertEqual(packet[6] & 0xf0, 0)
                                self.assertEqual(packet[9], service)
                                self.assertEqual(packet[10:], b"\x0c\x03\xc0\x00\x01\x1a\x02\x58" + encoded_index + b"\x3e" + body + b"\x3f")
                                reply = b"\x81\x0a\x00\x09\x01\x00\x20" + bytes((packet[8], service))
                                await loop.sock_sendto(peer, reply, sender)
                                await asyncio.wait_for(operation, 2)

    async def test_change_list_error_reaches_python_with_its_element_number(self):
        loop = asyncio.get_running_loop()
        # ChangeList-Error: [0] { SERVICES 5, LIST_ELEMENT_NOT_FOUND 81 } then [1] 2.
        # A device answering with only the class and code gives no element number.
        replies = ((b"\x0e\x91\x05\x91\x51\x0f\x19\x02", 2), (b"\x91\x05\x91\x51", None))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            async with BACnetClient(interface="127.0.0.1", port=0) as client:
                for body, element in replies:
                    for service, call in zip((8, 9), calls(client, b"\x21\x01\x21\x02", None, address)):
                        with self.subTest(service=service, element=element):
                            operation = call()
                            packet, sender = await asyncio.wait_for(loop.sock_recvfrom(peer, 2048), 2)
                            npdu = b"\x01\x00" + bytes((0x50, packet[8], service)) + body
                            reply = b"\x81\x0a" + (4 + len(npdu)).to_bytes(2, "big") + npdu
                            await loop.sock_sendto(peer, reply, sender)
                            with self.assertRaises(BacnetProtocolError) as raised:
                                await asyncio.wait_for(operation, 2)
                            self.assertEqual(raised.exception.error_class, 5)
                            self.assertEqual(raised.exception.error_code, 81)
                            self.assertEqual(raised.exception.first_failed_element_number, element)
