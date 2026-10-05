"""Installed-wheel Device_Address_Binding: the server's device bindings, read typed (#1369)."""
import unittest

from rusty_bacnet import BACnetServer, ObjectIdentifier, ObjectType, PropertyIdentifier


class DeviceAddressBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_configured_binding_reads_back_as_an_address_binding(self):
        server = BACnetServer(503_810, interface="127.0.0.1", port=0,
                              broadcast_address="127.0.0.1")
        server.add_device_binding(9, "10.0.0.9:47808")
        await server.start()
        try:
            value = await server.read_property(
                ObjectIdentifier(ObjectType.DEVICE, 503_810),
                PropertyIdentifier.DEVICE_ADDRESS_BINDING)
        finally:
            await server.stop()
        self.assertEqual(value.tag, "list")
        self.assertEqual(value.value, [{
            "device_identifier": ObjectIdentifier(ObjectType.DEVICE, 9),
            # On this network: network 0, and the B/IP MAC of 10.0.0.9:47808.
            "network_number": 0,
            "mac_address": bytes([10, 0, 0, 9, 0xBA, 0xC0]),
        }])


if __name__ == "__main__":
    unittest.main()
