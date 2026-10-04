"""Installed-artifact tests for add_access_rights(accompaniment=...) (#1393).

Accompaniment is Access Rights' optional BACnetDeviceObjectReference row. The
keyword serves it; without the keyword the object has no such row and a
client can't add one. Once served, clients read and write it, and with
storage_path a written reference is kept across a restart.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from rusty_bacnet import (
    BACnetClient,
    BACnetServer,
    BacnetProtocolError,
    ErrorCode,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

ACCOMPANIMENT = PropertyIdentifier.ACCOMPANIMENT
REMOTE_DEVICE = ObjectIdentifier(ObjectType.DEVICE, 99)
USER = ObjectIdentifier(ObjectType.ACCESS_USER, 3)
CREDENTIAL = ObjectIdentifier(ObjectType.ACCESS_CREDENTIAL, 5)
POINT = ObjectIdentifier(ObjectType.ACCESS_POINT, 1)

# A BACnetDeviceObjectReference: the device identifier [0] when present, then
# the object identifier [1].
USER_REFERENCE = bytes([0x1C, 0x08, 0xC0, 0x00, 0x03])
REMOTE_CREDENTIAL_REFERENCE = bytes(
    [0x0C, 0x02, 0x00, 0x00, 0x63, 0x1C, 0x08, 0x00, 0x00, 0x05]
)
POINT_REFERENCE = bytes([0x1C, 0x08, 0x40, 0x00, 0x01])


def rights_oid(instance: int) -> ObjectIdentifier:
    return ObjectIdentifier(ObjectType.ACCESS_RIGHTS, instance)


def make_server() -> BACnetServer:
    return BACnetServer(
        device_instance=503_393,
        device_name="Access Rights Accompaniment Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )


class AccompanimentTests(unittest.TestCase):
    def assert_error(self, raised: BacnetProtocolError, code: ErrorCode) -> None:
        self.assertEqual(raised.error_code, code.to_raw())

    def test_the_keyword_serves_the_row_and_clients_write_it(self) -> None:
        asyncio.run(self._served_and_written())

    async def _served_and_written(self) -> None:
        server = make_server()
        server.add_access_rights(1, "Escorted", accompaniment=USER)
        server.add_access_rights(
            2, "Remote Escort", accompaniment=(REMOTE_DEVICE, CREDENTIAL)
        )
        server.add_access_rights(3, "Unescorted")
        await server.start()
        try:
            address = await server.local_address()
            async with BACnetClient(
                interface="127.0.0.1", port=0, apdu_timeout_ms=2000
            ) as client:

                async def read(instance: int) -> bytes:
                    value = await client.read_property(
                        address, rights_oid(instance), ACCOMPANIMENT
                    )
                    # A local read sees what a client does.
                    self.assertEqual(
                        await server.read_property(rights_oid(instance), ACCOMPANIMENT),
                        value,
                    )
                    return value.value

                async def write(instance: int, octets: bytes) -> None:
                    await client.write_property(
                        address,
                        rights_oid(instance),
                        ACCOMPANIMENT,
                        PropertyValue.application_data(octets),
                    )

                self.assertEqual(await read(1), USER_REFERENCE)
                self.assertEqual(await read(2), REMOTE_CREDENTIAL_REFERENCE)

                # Without the keyword there is no row to read or write.
                with self.assertRaises(BacnetProtocolError) as raised:
                    await client.read_property(address, rights_oid(3), ACCOMPANIMENT)
                self.assert_error(raised.exception, ErrorCode.UNKNOWN_PROPERTY)
                with self.assertRaises(BacnetProtocolError) as raised:
                    await write(3, USER_REFERENCE)
                self.assert_error(raised.exception, ErrorCode.UNKNOWN_PROPERTY)

                # A client rewrites a served one.
                await write(1, REMOTE_CREDENTIAL_REFERENCE)
                self.assertEqual(await read(1), REMOTE_CREDENTIAL_REFERENCE)
                # An Access Point is refused, and the reference stays.
                with self.assertRaises(BacnetProtocolError) as raised:
                    await write(1, POINT_REFERENCE)
                self.assert_error(raised.exception, ErrorCode.VALUE_OUT_OF_RANGE)
                self.assertEqual(await read(1), REMOTE_CREDENTIAL_REFERENCE)
                # A NULL succeeds and changes nothing (#1396).
                await client.write_property(
                    address, rights_oid(1), ACCOMPANIMENT, PropertyValue.null()
                )
                self.assertEqual(await read(1), REMOTE_CREDENTIAL_REFERENCE)
        finally:
            await server.stop()

    def test_ill_formed_accompaniments_register_nothing(self) -> None:
        server = BACnetServer(9884)
        not_a_device = ObjectIdentifier(ObjectType.ANALOG_VALUE, 99)
        # Neither an ObjectIdentifier nor a (device, object) pair.
        for accompaniment in ("user", [USER], (USER,), (REMOTE_DEVICE, USER, USER)):
            with self.subTest(accompaniment=accompaniment), self.assertRaises(TypeError):
                server.add_access_rights(1, "Wrong", accompaniment=accompaniment)
        # A device member that isn't a Device (#1285).
        with self.assertRaises(ValueError):
            server.add_access_rights(1, "Wrong", accompaniment=(not_a_device, USER))
        # An object Clause 12.34.11 gives no meaning to.
        for accompaniment in (POINT, (REMOTE_DEVICE, POINT)):
            with self.subTest(accompaniment=accompaniment):
                with self.assertRaises(BacnetProtocolError) as raised:
                    server.add_access_rights(1, "Wrong", accompaniment=accompaniment)
                self.assert_error(raised.exception, ErrorCode.VALUE_OUT_OF_RANGE)
        self.assertEqual(server._pending_registration_count(), 0)
        # Instance 4194303 asks for no accompaniment, whatever the type.
        server.add_access_rights(
            1, "No escort", accompaniment=ObjectIdentifier(ObjectType.ACCESS_POINT, 4194303)
        )
        self.assertEqual(server._pending_registration_count(), 1)


class AccompanimentRestartTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_written_accompaniment_survives_a_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "rights-1")

            async def start(**keywords) -> BACnetServer:
                server = BACnetServer(9885, interface="127.0.0.1", port=0)
                server.add_access_rights(1, "Kept", storage_path=path, **keywords)
                await server.start()
                return server

            server = await start(accompaniment=USER)
            try:
                await server.write_property_local(
                    rights_oid(1),
                    ACCOMPANIMENT,
                    PropertyValue.application_data(REMOTE_CREDENTIAL_REFERENCE),
                    source_object=None,
                )
            finally:
                await server.stop()

            # The written reference wins over the keyword, and is served
            # without one too.
            for keywords in ({"accompaniment": USER}, {}):
                server = await start(**keywords)
                try:
                    value = await asyncio.wait_for(
                        server.read_property(rights_oid(1), ACCOMPANIMENT), 3
                    )
                    self.assertEqual(value.value, REMOTE_CREDENTIAL_REFERENCE, keywords)
                finally:
                    await server.stop()


if __name__ == "__main__":
    unittest.main()
