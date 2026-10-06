"""Installed-artifact tests for an Access Point's authentication policies (#1325).

add_access_point(authentication_policies=...) sets Authentication_Policy_List
and Authentication_Policy_Names as (name, policy) pairs, and the policy count
with them; none of the three takes a network write. A policy in effect that
isn't usable leaves Active_Authentication_Policy at 0 and Reliability at
CONFIGURATION_ERROR until a usable one is written, and Reliability takes
simulated writes only while the point is out of service.
"""

from __future__ import annotations

import asyncio
import unittest

from rusty_bacnet import (
    BACnetServer,
    BacnetProtocolError,
    ErrorCode,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

P = PropertyIdentifier
POINT = ObjectIdentifier(ObjectType.ACCESS_POINT, 1)
CARD_READER = ObjectIdentifier(ObjectType.CREDENTIAL_DATA_INPUT, 1)
KEYPAD = ObjectIdentifier(ObjectType.CREDENTIAL_DATA_INPUT, 2)
REMOTE_DEVICE = ObjectIdentifier(ObjectType.DEVICE, 99)
CARD = ([(CARD_READER, 1)], True, 30)
CARD_AND_PIN = ([(CARD_READER, 1), ((REMOTE_DEVICE, KEYPAD), 2)], False, 0)
EMPTY = ([], False, 0)
NO_FAULT_DETECTED = 0
UNRELIABLE_OTHER = 7
CONFIGURATION_ERROR = 10


def make_server() -> BACnetServer:
    return BACnetServer(
        device_instance=501_325,
        device_name="Access Point Policy Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )


class AccessPointPolicyTests(unittest.TestCase):
    def assert_error(self, error: BacnetProtocolError, code: ErrorCode) -> None:
        self.assertEqual(error.error_code, code.to_raw())

    def test_policies_reach_both_arrays_and_the_count(self) -> None:
        asyncio.run(self._policies())

    async def _policies(self) -> None:
        server = make_server()
        server.add_access_point(
            1,
            "Lobby",
            authentication_policies=[("card", CARD), ("card and PIN", CARD_AND_PIN)],
        )
        # A count given as well resizes both arrays after them.
        server.add_access_point(
            2, "Side", authentication_policies=[("card", CARD)],
            number_of_authentication_policies=2,
        )
        await server.start()
        try:
            async def value(point: ObjectIdentifier, prop: PropertyIdentifier,
                            index: int | None = None):
                return (await server.read_property(point, prop, index)).value

            self.assertEqual(await value(POINT, P.NUMBER_OF_AUTHENTICATION_POLICIES), 2)
            self.assertEqual(
                await value(POINT, P.AUTHENTICATION_POLICY_LIST), [CARD, CARD_AND_PIN]
            )
            self.assertEqual(
                await value(POINT, P.AUTHENTICATION_POLICY_NAMES), ["card", "card and PIN"]
            )
            self.assertEqual(await value(POINT, P.AUTHENTICATION_POLICY_LIST, 0), 2)
            self.assertEqual(await value(POINT, P.AUTHENTICATION_POLICY_LIST, 2), CARD_AND_PIN)
            side = ObjectIdentifier(ObjectType.ACCESS_POINT, 2)
            self.assertEqual(await value(side, P.AUTHENTICATION_POLICY_LIST), [CARD, EMPTY])
            self.assertEqual(await value(side, P.AUTHENTICATION_POLICY_NAMES), ["card", ""])

            # Read-only over the network, the count included.
            for prop, written in (
                (P.AUTHENTICATION_POLICY_NAMES,
                 PropertyValue.list([PropertyValue.character_string("x")])),
                (P.NUMBER_OF_AUTHENTICATION_POLICIES, PropertyValue.unsigned(1)),
            ):
                with self.assertRaises(BacnetProtocolError) as raised:
                    await server.write_property_local(POINT, prop, written, source_object=None)
                self.assert_error(raised.exception, ErrorCode.WRITE_ACCESS_DENIED)
            self.assertEqual(await value(POINT, P.NUMBER_OF_AUTHENTICATION_POLICIES), 2)
        finally:
            await server.stop()

    def test_an_unusable_policy_in_effect_is_a_configuration_error(self) -> None:
        asyncio.run(self._unusable())

    async def _unusable(self) -> None:
        server = make_server()
        server.add_access_point(
            1, "Lobby", authentication_policies=[("empty", EMPTY), ("card", CARD)]
        )
        await server.start()
        try:
            async def value(prop: PropertyIdentifier):
                return (await server.read_property(POINT, prop)).value

            async def write(prop: PropertyIdentifier, written: PropertyValue) -> None:
                await server.write_property_local(POINT, prop, written, source_object=None)

            self.assertEqual(await value(P.ACTIVE_AUTHENTICATION_POLICY), 0)
            self.assertEqual(await value(P.RELIABILITY), CONFIGURATION_ERROR)
            # The empty policy can't be put in effect; the card policy can.
            with self.assertRaises(BacnetProtocolError) as raised:
                await write(P.ACTIVE_AUTHENTICATION_POLICY, PropertyValue.unsigned(1))
            self.assert_error(raised.exception, ErrorCode.VALUE_OUT_OF_RANGE)
            await write(P.ACTIVE_AUTHENTICATION_POLICY, PropertyValue.unsigned(2))
            self.assertEqual(await value(P.ACTIVE_AUTHENTICATION_POLICY), 2)
            self.assertEqual(await value(P.RELIABILITY), NO_FAULT_DETECTED)

            # Reliability takes a simulated value only out of service.
            simulated = PropertyValue.enumerated(UNRELIABLE_OTHER)
            with self.assertRaises(BacnetProtocolError) as raised:
                await write(P.RELIABILITY, simulated)
            self.assert_error(raised.exception, ErrorCode.WRITE_ACCESS_DENIED)
            await write(P.OUT_OF_SERVICE, PropertyValue.boolean(True))
            await write(P.RELIABILITY, simulated)
            self.assertEqual(await value(P.RELIABILITY), UNRELIABLE_OTHER)
            await write(P.OUT_OF_SERVICE, PropertyValue.boolean(False))
            self.assertEqual(await value(P.RELIABILITY), NO_FAULT_DETECTED)
        finally:
            await server.stop()

    def test_malformed_keywords_register_nothing(self) -> None:
        server = make_server()
        with self.assertRaises(BacnetProtocolError) as raised:
            server.add_access_point(1, "None", authentication_policies=[])
        self.assert_error(raised.exception, ErrorCode.VALUE_OUT_OF_RANGE)
        not_a_device = ObjectIdentifier(ObjectType.ANALOG_VALUE, 99)
        for policies, error in (
            ([CARD], TypeError),  # no name
            ([("card", ([(CARD_READER, 1)], 1, 30))], TypeError),  # not a bool
            ([("card", ([(CARD_READER, 1)], True))], TypeError),  # no timeout
            ([("card", ([((not_a_device, CARD_READER), 1)], True, 30))], ValueError),
            ([("card", ([(CARD_READER, 2**32)], True, 30))], OverflowError),
        ):
            with self.subTest(policies=policies):
                with self.assertRaises(error):
                    server.add_access_point(2, "Wrong", authentication_policies=policies)


if __name__ == "__main__":
    unittest.main()
