"""Transport I/O failures are OSErrors with errno, and still BacnetErrors (#1120)."""
import asyncio
import errno
import socket
import unittest

from rusty_bacnet import (
    BACnetClient, BACnetServer, BacnetError, BacnetTransportError, BipEndpoint,
)
from test_sc_hub_lifecycle import HubTlsFixture


def assert_addr_in_use(case: unittest.TestCase, error: BaseException) -> None:
    case.assertIsInstance(error, OSError)
    case.assertIsInstance(error, BacnetError)
    case.assertIsInstance(error, BacnetTransportError)
    case.assertEqual(error.errno, errno.EADDRINUSE)
    case.assertTrue(error.strerror)


class ScHubBindTests(HubTlsFixture):
    async def test_occupied_port_raises_oserror_with_eaddrinuse(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            hub = self.make_hub(listen=f"127.0.0.1:{occupied.getsockname()[1]}")
            with self.assertRaises(OSError) as raised:
                await asyncio.wait_for(hub.start(), 10)
            assert_addr_in_use(self, raised.exception)
            self.assertIsNone(await hub.address())


class BipBindTests(unittest.IsolatedAsyncioTestCase):
    async def test_endpoint_on_occupied_udp_port_raises_oserror(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("0.0.0.0", 0))
            endpoint = BipEndpoint(
                device_instance=1001, vendor_id=42, interface="127.0.0.1",
                port=occupied.getsockname()[1],
                broadcast_address="127.255.255.255",
            )
            with self.assertRaises(OSError) as raised:
                await asyncio.wait_for(endpoint.start(), 10)
            assert_addr_in_use(self, raised.exception)

    async def test_server_on_occupied_udp_port_raises_oserror(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("0.0.0.0", 0))
            server = BACnetServer(
                1002, interface="127.0.0.1", port=occupied.getsockname()[1])
            with self.assertRaises(OSError) as raised:
                await asyncio.wait_for(server.start(), 10)
            assert_addr_in_use(self, raised.exception)

    async def test_client_on_occupied_udp_port_raises_oserror(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("0.0.0.0", 0))
            client = BACnetClient(
                interface="127.0.0.1", port=occupied.getsockname()[1])
            with self.assertRaises(OSError) as raised:
                await asyncio.wait_for(client.__aenter__(), 10)
            assert_addr_in_use(self, raised.exception)


if __name__ == "__main__":
    unittest.main()
