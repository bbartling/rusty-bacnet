"""Installed Virtual Terminal client methods: independent wire vectors and strict ACK decoding."""
import asyncio
import socket
import unittest

from rusty_bacnet import BacnetError, BACnetClient, VTClass

VT_OPEN, VT_CLOSE, VT_DATA = 21, 22, 23


def complex_ack(packet: bytes, service: int, payload: bytes) -> bytes:
    body = b"\x01\x00" + bytes((0x30, packet[8], service)) + payload
    return b"\x81\x0a" + (4 + len(body)).to_bytes(2, "big") + body


def simple_ack(packet: bytes, service: int) -> bytes:
    body = b"\x01\x00" + bytes((0x20, packet[8], service))
    return b"\x81\x0a" + (4 + len(body)).to_bytes(2, "big") + body


class VirtualTerminalTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, call, service, reply_for):
        """Run one client call against a UDP peer; return (request payload, call result)."""
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            async with BACnetClient(interface="127.0.0.1", port=0) as client:
                operation = call(client, address)
                packet, sender = await asyncio.wait_for(loop.sock_recvfrom(peer, 2048), 2)
                self.assertEqual(packet[:2], b"\x81\x0a")
                self.assertEqual(packet[4:6], b"\x01\x04")
                self.assertEqual(packet[6] & 0xF0, 0)
                self.assertEqual(packet[9], service)
                await loop.sock_sendto(peer, reply_for(packet), sender)
                return packet[10:], await asyncio.wait_for(operation, 2)

    async def test_vt_open_sends_class_and_local_identifier(self):
        payload, remote = await self.exchange(
            lambda client, address: client.vt_open(address, VTClass.DEFAULT_TERMINAL, 5),
            VT_OPEN,
            lambda packet: complex_ack(packet, VT_OPEN, b"\x21\x2a"),
        )
        self.assertEqual(payload, bytes.fromhex("91002105"))
        self.assertEqual(remote, 42)

    async def test_vt_open_other_class_and_identifier_range(self):
        payload, _ = await self.exchange(
            lambda client, address: client.vt_open(address, VTClass.DEC_VT100, 255),
            VT_OPEN,
            lambda packet: complex_ack(packet, VT_OPEN, b"\x21\x00"),
        )
        self.assertEqual(payload, bytes.fromhex("910321ff"))
        async with BACnetClient(interface="127.0.0.1", port=0) as client:
            for bad in (256, -1):
                with self.assertRaises(OverflowError):
                    await client.vt_open("127.0.0.1:47808", VTClass.DEFAULT_TERMINAL, bad)

    async def test_vt_data_flag_is_unsigned_and_ack_is_always_boolean(self):
        payload, ack = await self.exchange(
            lambda client, address: client.vt_data(address, 1, b"Hi", True),
            VT_DATA,
            lambda packet: complex_ack(packet, VT_DATA, bytes.fromhex("0901")),
        )
        self.assertEqual(payload, bytes.fromhex("2101624869" "2101"))
        self.assertEqual(ack, {"all_new_data_accepted": True, "accepted_octet_count": None})

        payload, ack = await self.exchange(
            lambda client, address: client.vt_data(address, 1, b"Hi", False),
            VT_DATA,
            lambda packet: complex_ack(packet, VT_DATA, bytes.fromhex("09001903")),
        )
        self.assertEqual(payload, bytes.fromhex("2101624869" "2100"))
        self.assertEqual(ack, {"all_new_data_accepted": False, "accepted_octet_count": 3})

    async def test_vt_data_rejects_non_conformant_acks(self):
        for label, ack in (
            ("empty", b""),
            ("count only", bytes.fromhex("1903")),
            ("true with count", bytes.fromhex("09011903")),
            ("false without count", bytes.fromhex("0900")),
            ("trailing", bytes.fromhex("090121" "00")),
        ):
            with self.subTest(ack=label):
                with self.assertRaises(BacnetError):
                    await self.exchange(
                        lambda client, address: client.vt_data(address, 1, b"x", False),
                        VT_DATA,
                        lambda packet, ack=ack: complex_ack(packet, VT_DATA, ack),
                    )

    async def test_vt_close_sends_identifier_list(self):
        payload, _ = await self.exchange(
            lambda client, address: client.vt_close(address, [1, 2]),
            VT_CLOSE,
            lambda packet: simple_ack(packet, VT_CLOSE),
        )
        self.assertEqual(payload, bytes.fromhex("21012102"))

    async def test_vt_close_empty_list_is_rejected_before_sending(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.setblocking(False)
            address = f"127.0.0.1:{peer.getsockname()[1]}"
            async with BACnetClient(interface="127.0.0.1", port=0) as client:
                with self.assertRaises(ValueError):
                    await client.vt_close(address, [])
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(
                        asyncio.get_running_loop().sock_recvfrom(peer, 2048), 0.1
                    )


if __name__ == "__main__":
    unittest.main()
