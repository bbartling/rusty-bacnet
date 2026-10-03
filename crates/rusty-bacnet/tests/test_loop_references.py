"""Installed-artifact tests for the Loop and Pulse Converter references (#1312).

Controlled_Variable_Reference, Manipulated_Variable_Reference and Input_Reference
read as ``application_data`` holding the context-tagged
BACnetObjectPropertyReference, and Setpoint_Reference holding the
BACnetSetpointReference. They take writes in those encodings, locally and over
the network, and refuse the flat list they used to read as with
INVALID_DATA_TYPE.
"""

from __future__ import annotations

import unittest

from rusty_bacnet import (
    BACnetClient,
    BACnetServer,
    BacnetProtocolError,
    ErrorClass,
    ErrorCode,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

P = PropertyIdentifier
LOOP = ObjectIdentifier(ObjectType.LOOP, 1)
PC = ObjectIdentifier(ObjectType.PULSE_CONVERTER, 1)
AI_7 = ObjectIdentifier(ObjectType.ANALOG_INPUT, 7)
# [0] analog-input 7, [1] present-value (85).
AI_7_PV = bytes([0x0C, 0x00, 0x00, 0x00, 0x07, 0x19, 0x55])
# The same reference inside a BACnetSetpointReference: opening and closing tag 0.
AI_7_PV_FRAMED = b"\x0e" + AI_7_PV + b"\x0f"
FLAT = PropertyValue.list(
    [PropertyValue.object_identifier(AI_7), PropertyValue.enumerated(85)]
)


def make_server() -> BACnetServer:
    server = BACnetServer(
        device_instance=1_312_001,
        device_name="Loop Reference Artifact Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )
    server.add_loop(1, "LOOP-1")
    server.add_pulse_converter(1, "PC-1", 95)
    return server


class LoopReferenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = make_server()
        await self.server.start()

        async def stop_server() -> None:
            await self.server.stop()

        self.addAsyncCleanup(stop_server)
        self.address = await self.server.local_address()
        self.client = BACnetClient(interface="127.0.0.1", port=0, apdu_timeout_ms=2000)
        await self.client.__aenter__()

        async def stop_client() -> None:
            await self.client.__aexit__(None, None, None)

        self.addAsyncCleanup(stop_client)

    async def test_unset_references_read_null_or_the_empty_setpoint_reference(self) -> None:
        for oid, prop in ((LOOP, P.CONTROLLED_VARIABLE_REFERENCE),
                          (LOOP, P.MANIPULATED_VARIABLE_REFERENCE),
                          (PC, P.INPUT_REFERENCE)):
            with self.subTest(property=prop):
                self.assertEqual(await self.server.read_property(oid, prop), PropertyValue.null())
        # A Setpoint_Reference without a reference has no octets.
        self.assertEqual(
            await self.server.read_property(LOOP, P.SETPOINT_REFERENCE), PropertyValue.list([])
        )

    async def test_references_read_and_write_in_their_encodings(self) -> None:
        for oid, prop, octets in ((LOOP, P.CONTROLLED_VARIABLE_REFERENCE, AI_7_PV),
                                  (LOOP, P.MANIPULATED_VARIABLE_REFERENCE, AI_7_PV),
                                  (LOOP, P.SETPOINT_REFERENCE, AI_7_PV_FRAMED),
                                  (PC, P.INPUT_REFERENCE, AI_7_PV)):
            with self.subTest(property=prop):
                await self.client.write_property(
                    self.address, oid, prop, PropertyValue.application_data(octets)
                )
                for value in (await self.server.read_property(oid, prop),
                              await self.client.read_property(self.address, oid, prop)):
                    self.assertEqual(value.tag, "application_data")
                    self.assertEqual(value.value, octets)
                # The value read writes back locally unchanged.
                value = await self.server.read_property(oid, prop)
                await self.server.write_property_local(oid, prop, value, source_object=None)
                self.assertEqual(await self.server.read_property(oid, prop), value)

    async def test_flat_list_is_refused_and_changes_nothing(self) -> None:
        for oid, prop in ((LOOP, P.CONTROLLED_VARIABLE_REFERENCE),
                          (LOOP, P.MANIPULATED_VARIABLE_REFERENCE),
                          (LOOP, P.SETPOINT_REFERENCE),
                          (PC, P.INPUT_REFERENCE)):
            with self.subTest(property=prop):
                before = await self.server.read_property(oid, prop)
                with self.assertRaises(BacnetProtocolError) as network:
                    await self.client.write_property(self.address, oid, prop, FLAT)
                with self.assertRaises(BacnetProtocolError) as local:
                    await self.server.write_property_local(oid, prop, FLAT, source_object=None)
                for raised in (network.exception, local.exception):
                    self.assertEqual(raised.error_class, ErrorClass.PROPERTY.to_raw())
                    self.assertEqual(raised.error_code, ErrorCode.INVALID_DATA_TYPE.to_raw())
                self.assertEqual(await self.server.read_property(oid, prop), before)

    async def test_null_or_the_empty_setpoint_reference_clears(self) -> None:
        await self.client.write_property(
            self.address, LOOP, P.CONTROLLED_VARIABLE_REFERENCE,
            PropertyValue.application_data(AI_7_PV),
        )
        await self.client.write_property(
            self.address, LOOP, P.SETPOINT_REFERENCE,
            PropertyValue.application_data(AI_7_PV_FRAMED),
        )
        await self.client.write_property(
            self.address, LOOP, P.CONTROLLED_VARIABLE_REFERENCE, PropertyValue.null()
        )
        await self.client.write_property(
            self.address, LOOP, P.SETPOINT_REFERENCE, PropertyValue.list([])
        )
        self.assertEqual(
            await self.server.read_property(LOOP, P.CONTROLLED_VARIABLE_REFERENCE),
            PropertyValue.null(),
        )
        self.assertEqual(
            await self.server.read_property(LOOP, P.SETPOINT_REFERENCE), PropertyValue.list([])
        )
        # Null isn't a BACnetSetpointReference.
        with self.assertRaises(BacnetProtocolError) as raised:
            await self.client.write_property(
                self.address, LOOP, P.SETPOINT_REFERENCE, PropertyValue.null()
            )
        self.assertEqual(raised.exception.error_code, ErrorCode.INVALID_DATA_TYPE.to_raw())


if __name__ == "__main__":
    unittest.main()
