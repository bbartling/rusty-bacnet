"""Active B/IP address comes from the owned bind, including ephemeral ports."""
import asyncio
import socket
import unittest

from rusty_bacnet import BipEndpoint


class BoundAddressTests(unittest.IsolatedAsyncioTestCase):
    async def test_inactive_and_closed_address_refuse(self):
        endpoint = BipEndpoint(device_instance=785, interface="127.0.0.1", port=0)
        with self.assertRaises(RuntimeError):
            await endpoint.local_address()
        await endpoint.start()
        await endpoint.close()
        with self.assertRaises(RuntimeError):
            await endpoint.local_address()
        with self.assertRaises(RuntimeError):
            await endpoint.status()

    async def test_ephemeral_snapshot_matches_observed_source(self):
        # A raw peer independently observes the address rather than trusting status.
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind(("127.0.0.1", 0))
        peer.setblocking(False)
        endpoint = BipEndpoint(device_instance=786, interface="127.0.0.1", port=0)
        try:
            await endpoint.start()
            address = await endpoint.local_address()
            host, port = address.rsplit(":", 1)
            self.assertEqual(host, "127.0.0.1")
            self.assertNotEqual(int(port), 0)
            self.assertEqual((await endpoint.status())["local_address"], address)
            # Independent RP of Device:786 Object_Identifier (invoke ID 1).
            await asyncio.get_running_loop().sock_sendto(
                peer, bytes.fromhex("810a001101000005010c0c02000312194b"), (host, int(port))
            )
            reply, source = await asyncio.wait_for(
                asyncio.get_running_loop().sock_recvfrom(peer, 2048), 2
            )
            self.assertEqual(source, (host, int(port)))
            self.assertEqual(reply[6:9], bytes.fromhex("30010c"))
        finally:
            await endpoint.close()
            peer.close()

    async def test_unregistered_wildcard_interface_has_actual_address(self):
        endpoint = BipEndpoint(device_instance=787, port=0)
        try:
            await endpoint.start()
            address = await endpoint.local_address()
            host, port = address.rsplit(":", 1)
            self.assertNotEqual(host, "0.0.0.0")
            self.assertNotEqual(int(port), 0)
            self.assertEqual((await endpoint.status())["local_address"], address)
        finally:
            await endpoint.close()

    async def test_explicit_registration_in_both_python_owners(self):
        from rusty_bacnet import BACnetClient, BACnetServer, ObjectIdentifier, ObjectType, PropertyIdentifier as P, PropertyValue as V, BacnetProtocolError
        wildcard = ObjectIdentifier(ObjectType.NETWORK_PORT, 4194303)
        concrete = ObjectIdentifier(ObjectType.NETWORK_PORT, 2)
        for full in (False, True):
            with self.subTest(full_server=full):
                if full:
                    owner = BACnetServer(788, interface="127.0.0.1", port=0, registered_network_port=2)
                    owner.add_bip_network_port(1, "unrelated", ip_address="127.0.0.1", udp_port=11)
                    owner.add_bip_network_port(2, "selected", ip_address="127.0.0.1", udp_port=0)
                else:
                    owner = BipEndpoint(788, interface="127.0.0.1", port=0,
                                        network_port_instance=2, registered_network_port=2)
                await owner.start()
                try:
                    address = await owner.local_address()
                    udp = int(address.rsplit(":", 1)[1])
                    async with BACnetClient(interface="127.0.0.1", port=0) as client:
                        self.assertEqual(await client.read_property(address, wildcard, P.OBJECT_IDENTIFIER), V.object_identifier(concrete))
                        self.assertEqual(await client.read_property(address, wildcard, P.BACNET_IP_UDP_PORT), V.unsigned(udp))
                        self.assertEqual(await client.read_property(address, concrete, P.MAC_ADDRESS), V.octet_string(bytes([127, 0, 0, 1]) + udp.to_bytes(2, "big")))
                        if full:
                            with self.assertRaises(BacnetProtocolError):
                                await client.write_property(address, concrete, P.OUT_OF_SERVICE, V.boolean(True))
                finally:
                    if full:
                        await owner.stop()
                    else:
                        await owner.close()

    def test_registration_rejects_invalid_python_selection(self):
        from rusty_bacnet import BACnetServer
        for selected in (0, 256, 4194303):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                BipEndpoint(789, interface="127.0.0.1", port=0, registered_network_port=selected)
            with self.assertRaises(ValueError):
                BACnetServer(789, registered_network_port=selected)
        with self.assertRaises(ValueError):
            BipEndpoint(789, port=0, registered_network_port=1)
        with self.assertRaises(ValueError):
            BipEndpoint(789, interface="127.0.0.1", port=0, registered_network_port=2)
