"""A Device binding never takes a group address of the link (#1493).

add_device_binding parses the address; start() then refuses one that reaches
a group of nodes, a multicast address or the limited broadcast, and its error
names the device and the address. A binding at a station still starts.
"""
import unittest

import rusty_bacnet as rb


class GroupBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_refuses_a_binding_at_a_group_address(self) -> None:
        for address, octets in (
            ("224.0.0.1:47808", "e0:00:00:01:ba:c0"),
            ("239.255.255.250:47809", "ef:ff:ff:fa:ba:c1"),
            ("255.255.255.255:47808", "ff:ff:ff:ff:ba:c0"),
        ):
            with self.subTest(address=address):
                server = rb.BACnetServer(8731, interface="127.0.0.1", port=0)
                server.add_device_binding(9, address)
                with self.assertRaises(rb.BacnetError) as raised:
                    await server.start()
                message = str(raised.exception)
                self.assertIn(f"Device 9 is bound at {octets}", message)
                self.assertIn("broadcast or group address", message)

    async def test_start_takes_a_binding_at_a_station(self) -> None:
        server = rb.BACnetServer(8732, interface="127.0.0.1", port=0)
        server.add_device_binding(9, "127.0.0.1:47809")
        await server.start()
        await server.stop()


if __name__ == "__main__":
    unittest.main()
