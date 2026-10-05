"""One exception type for an integer argument outside its range (#1360).

An integer outside the fixed-width type of the field it fills (negative for
an unsigned field, or too wide) raises OverflowError, whether it is a
parameter, a tuple member or a mapping value. A value that fits the type but
that BACnet doesn't allow raises ValueError when the binding checks it while
reading the argument, and BacnetProtocolError (VALUE_OUT_OF_RANGE) when the
object's own check refuses it.
"""

from __future__ import annotations

import unittest
from typing import Any, Callable

from rusty_bacnet import (
    BACnetServer,
    BACnetTimeStamp,
    BacnetProtocolError,
    ErrorCode,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    PropertyValue,
)

AO1 = ObjectIdentifier(ObjectType.ANALOG_OUTPUT, 1)
SCHEDULE = ObjectIdentifier(ObjectType.SCHEDULE, 1)
PV = PropertyIdentifier.PRESENT_VALUE
DEVICE_9 = {"kind": "device", "object_identifier": ObjectIdentifier(ObjectType.DEVICE, 9)}


def action(**command: Any) -> Any:
    return [[{"object_identifier": AO1, "property_identifier": PV,
              "property_value": PropertyValue.real(1.0), **command}]]


def rule(index: int) -> Any:
    return [{"enable": True, "time_range": {"object_identifier": SCHEDULE,
                                            "property_identifier": PV,
                                            "property_array_index": index}}]


# Each case: a call taking one integer, the value that overflows its type,
# and a value inside the type that BACnet refuses, with the error that gets.
CASES: list[tuple[str, Callable[[BACnetServer, Any], None], Any, Any, type[Exception]]] = [
    ("add_access_point priority_for_writing (parameter)",
     lambda server, value: server.add_access_point(1, "AP", priority_for_writing=value),
     256, 17, BacnetProtocolError),
    ("add_loop priority_for_writing (parameter)",
     lambda server, value: server.add_loop(1, "LOOP", priority_for_writing=value),
     264, 0, BacnetProtocolError),
    ("add_channel channel_number (parameter)",
     lambda server, value: server.add_channel(1, "CH", value),
     65_536, None, BacnetProtocolError),
    ("add_command priority (mapping)",
     lambda server, value: server.add_command(1, "CMD", action=action(priority=value)),
     256, 17, BacnetProtocolError),
    ("add_command property_array_index (mapping)",
     lambda server, value: server.add_command(
         1, "CMD", action=action(property_array_index=value)),
     2**32, None, BacnetProtocolError),
    ("add_channel member index (tuple)",
     lambda server, value: server.add_channel(1, "CH", 1, [(AO1, PV, value)]),
     2**32, None, BacnetProtocolError),
    ("add_channel member index (mapping)",
     lambda server, value: server.add_channel(1, "CH", 1, [
         {"object_identifier": AO1, "property_identifier": PV, "property_array_index": value}]),
     -1, None, BacnetProtocolError),
    ("add_access_rights time_range index (mapping)",
     lambda server, value: server.add_access_rights(1, "AR", positive_access_rules=rule(value)),
     2**32, None, BacnetProtocolError),
    ("add_credential_data_input vendor id (tuple)",
     lambda server, value: server.add_credential_data_input(
         1, "CDI", supported_formats=[((2, value, 7), 0)]),
     65_536, None, BacnetProtocolError),
    ("add_notification_class process_identifier (mapping)",
     lambda server, value: server.add_notification_class(
         1, "NC", recipients=[{"recipient": DEVICE_9, "process_identifier": value}]),
     2**32, None, BacnetProtocolError),
    ("add_notification_class valid_days (mapping)",
     lambda server, value: server.add_notification_class(
         1, "NC", recipients=[{"recipient": DEVICE_9, "process_identifier": 1,
                               "valid_days": value}]),
     256, 128, ValueError),
    ("add_accumulator scale (parameter)",
     lambda server, value: server.add_accumulator(1, "ACC", scale=value),
     2**31, None, BacnetProtocolError),
    ("add_accumulator prescale (tuple)",
     lambda server, value: server.add_accumulator(1, "ACC", prescale=(value, 100)),
     -1, None, BacnetProtocolError),
]


class IntegerRangeErrorTests(unittest.TestCase):
    def test_outside_the_type_overflows_and_inside_it_bacnet_decides(self) -> None:
        for case, call, overflows, refused, error in CASES:
            with self.subTest(case=case):
                server = BACnetServer(9360, interface="127.0.0.1", port=0)
                with self.assertRaises(OverflowError):
                    call(server, overflows)
                if refused is not None:
                    with self.assertRaises(error) as raised:
                        call(server, refused)
                    if error is BacnetProtocolError:
                        self.assertEqual(raised.exception.error_code,
                                         ErrorCode.VALUE_OUT_OF_RANGE.to_raw())
                # Nothing is registered after a refusal.
                self.assertEqual(server._pending_registration_count(), 0)

    def test_overflow_is_not_a_value_error(self) -> None:
        # Callers catching ValueError for a BACnet range check don't also
        # catch an overflow by accident, and the other way round.
        with self.assertRaises(OverflowError) as raised:
            BACnetTimeStamp.sequence_number(65_536)
        self.assertNotIsInstance(raised.exception, ValueError)
        with self.assertRaises(OverflowError):
            BACnetTimeStamp.time(256, 0, 0, 0)
        with self.assertRaises(ValueError) as refused:
            BACnetTimeStamp.time(24, 0, 0, 0)
        self.assertNotIsInstance(refused.exception, OverflowError)
        with self.assertRaises(OverflowError):
            BACnetTimeStamp.date_time((65_536, 1, 1, 1), (0, 0, 0, 0))
        with self.assertRaises(ValueError):
            BACnetTimeStamp.date_time((2155, 1, 1, 1), (0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
