"""Installed WriteGroup and Who-Am-I argument validation, WriteGroup destinations and exact
WriteGroup wire bytes."""
import asyncio
import socket
import unittest

from rusty_bacnet import BACnetClient

REAL_72 = bytes([0x44, 0x42, 0x90, 0x00, 0x00])


def invalid_write_groups():
    yield 0, 8, [(5, None, REAL_72)]  # group 0 is reserved
    yield 1, 0, [(5, None, REAL_72)]  # write priority below 1
    yield 1, 17, [(5, None, REAL_72)]  # write priority above 16
    yield 1, 8, []  # empty change list
    yield 1, 8, [(5, 0, REAL_72)]  # override priority below 1
    yield 1, 8, [(5, 17, REAL_72)]  # override priority above 16
    yield 1, 8, [(5, None, b"")]  # no value
    yield 1, 8, [(5, None, b"\x00\x00")]  # two values
    yield 1, 8, [(5, None, b"\x2e" + REAL_72 + b"\x2f")]  # wrapped in context tag 2
    yield 1, 8, [(5, None, b"\x44\x42\x90")]  # truncated REAL


class WriteGroupTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_arguments_raise_before_address_and_start(self):
        client = BACnetClient(interface="127.0.0.1", port=0)
        for group, priority, change_list in invalid_write_groups():
            with self.subTest(group=group, priority=priority, change_list=change_list):
                with self.assertRaises(ValueError):
                    client.write_group("invalid-address", group, priority, change_list)

    async def test_out_of_range_integers_overflow(self):
        client = BACnetClient(interface="127.0.0.1", port=0)
        for channel in (-1, 65536):
            with self.assertRaises(OverflowError):
                client.write_group("invalid-address", 1, 8, [(channel, None, REAL_72)])
        with self.assertRaises(OverflowError):
            client.write_group("invalid-address", 1 << 32, 8, [(5, None, REAL_72)])

    async def test_object_identifier_channel_is_rejected(self):
        from rusty_bacnet import ObjectIdentifier, ObjectType

        client = BACnetClient(interface="127.0.0.1", port=0)
        oid = ObjectIdentifier(ObjectType.CHANNEL, 5)
        with self.assertRaises(TypeError):
            client.write_group("invalid-address", 1, 8, [(oid, None, REAL_72)])

    async def test_destination_arguments(self):
        client = BACnetClient(interface="127.0.0.1", port=0)
        entry = [(5, None, REAL_72)]
        # An address and a network together, or network 0, are refused at once.
        with self.assertRaises(ValueError):
            client.write_group("127.0.0.1:47808", 1, 8, entry, network=5)
        with self.assertRaises(ValueError):
            client.write_group(None, 1, 8, entry, network=0)
        for network in (-1, 65536):
            with self.assertRaises(OverflowError):
                client.write_group(None, 1, 8, entry, network=network)
        # The network is keyword-only.
        with self.assertRaises(TypeError):
            client.write_group(None, 1, 8, entry, None, 5)
        # Valid broadcasts get as far as the client, which isn't started.
        for network in (None, 5, 65534, 65535):
            with self.subTest(network=network):
                with self.assertRaises(RuntimeError):
                    await client.write_group(None, 1, 8, entry, network=network)

    async def test_broadcasts_are_sent(self):
        # The broadcast address is the client's own, so each broadcast loops
        # back to it; the call returns once the request is on the link.
        async with BACnetClient(
            interface="127.0.0.1", port=0, broadcast_address="127.0.0.1"
        ) as client:
            for network in (None, 5, 65535):
                with self.subTest(network=network):
                    await client.write_group(
                        None, 1, 8, [(5, None, REAL_72)], True, network=network
                    )

    async def test_exact_wire_bytes(self):
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            async with BACnetClient(interface="127.0.0.1", port=0) as client:
                await client.write_group(address, 1, 8, [(5, None, REAL_72)])
                packet, _ = await asyncio.wait_for(loop.sock_recvfrom(peer, 2048), 2)
                # Unconfirmed-Request APDU, service choice 10, then the service data.
                self.assertEqual(packet[4:6], b"\x01\x00")
                self.assertEqual(packet[6:8], b"\x10\x0a")
                self.assertEqual(
                    packet[8:],
                    bytes.fromhex("09 01 19 08 2e 09 05 44 42 90 00 00 2f"),
                )

                await client.write_group(
                    address, 258, 16, [(300, 10, b"\x00"), (0, None, b"\x11")], True
                )
                packet, _ = await asyncio.wait_for(loop.sock_recvfrom(peer, 2048), 2)
                self.assertEqual(
                    packet[8:],
                    bytes.fromhex("0a 01 02 19 10 2e 0a 01 2c 19 0a 00 09 00 11 2f 39 01"),
                )


class WhoAmITests(unittest.IsolatedAsyncioTestCase):
    async def test_all_three_arguments_are_required(self):
        client = BACnetClient(interface="127.0.0.1", port=0)
        with self.assertRaises(TypeError):
            client.who_am_i()
        with self.assertRaises(TypeError):
            client.who_am_i(260, "M")

    async def test_vendor_id_must_fit_unsigned16(self):
        client = BACnetClient(interface="127.0.0.1", port=0)
        for vendor_id in (-1, 65536):
            with self.assertRaises(OverflowError):
                client.who_am_i(vendor_id, "M", "S")

    async def test_valid_call_needs_a_started_client(self):
        client = BACnetClient(interface="127.0.0.1", port=0)
        with self.assertRaises(RuntimeError):
            await client.who_am_i(260, "M", "S")


if __name__ == "__main__":
    unittest.main()
