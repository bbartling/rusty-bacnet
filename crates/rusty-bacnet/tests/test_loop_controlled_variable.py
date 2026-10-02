"""Installed-artifact tests for the Loop's application-fed rows (#1062, #1063).

`add_loop` takes the rows that are read-only over the network as keyword
arguments, checked like the Rust setters, and
`set_controlled_variable_value_local` feeds a running Loop's measurement.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import unittest
from pathlib import Path
from typing import Any

import rusty_bacnet
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


NOTIFICATION_TIMEOUT = 2.0
SILENCE_TIMEOUT = 0.25
LOOP = ObjectIdentifier(ObjectType.LOOP, 1)
AV = ObjectIdentifier(ObjectType.ANALOG_VALUE, 2)
CVV = PropertyIdentifier.CONTROLLED_VARIABLE_VALUE
LOOP_KEYWORDS = [
    "controlled_variable_units",
    "proportional_constant_units",
    "integral_constant_units",
    "derivative_constant_units",
    "priority_for_writing",
]


def installed_stub_method(name: str) -> ast.FunctionDef:
    stub_path = Path(rusty_bacnet.__file__).with_suffix(".pyi")
    tree = ast.parse(stub_path.read_text(encoding="utf-8"), filename=str(stub_path))
    server = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "BACnetServer"
    )
    return next(
        node
        for node in server.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def make_server(**loop_keywords: int) -> BACnetServer:
    server = BACnetServer(
        device_instance=1_063_001,
        device_name="Loop Controlled Variable Artifact Test",
        interface="127.0.0.1",
        port=0,
        broadcast_address="127.0.0.1",
    )
    server.add_loop(1, "LOOP-1", 98, **loop_keywords)
    server.add_analog_value(2, "AV-2")
    return server


def assert_protocol_error(
    case: unittest.TestCase,
    raised: BacnetProtocolError,
    error_class: ErrorClass,
    error_code: ErrorCode,
) -> None:
    case.assertEqual(raised.error_class, error_class.to_raw())
    case.assertEqual(raised.error_code, error_code.to_raw())


class LoopStubContractTests(unittest.TestCase):
    def test_runtime_and_stub_expose_the_controlled_variable_route(self) -> None:
        runtime = list(
            inspect.signature(
                BACnetServer.set_controlled_variable_value_local
            ).parameters
        )
        self.assertEqual(runtime, ["self", "object_id", "value"])
        method = installed_stub_method("set_controlled_variable_value_local")
        stub_args = [argument.arg for argument in method.args.args]
        self.assertEqual(stub_args, ["self", "object_id", "value"])
        self.assertEqual(ast.unparse(method.returns), "Awaitable[None]")
        docs = ast.get_docstring(method)
        assert docs is not None
        for phrase in ("finite REAL", "Out_Of_Service", "SubscribeCOVProperty"):
            with self.subTest(documented=phrase):
                self.assertIn(phrase, docs)

    def test_add_loop_takes_the_read_only_rows_as_keyword_only_arguments(
        self,
    ) -> None:
        parameters = inspect.signature(BACnetServer.add_loop).parameters
        keyword_only = [
            name
            for name, parameter in parameters.items()
            if parameter.kind is inspect.Parameter.KEYWORD_ONLY
        ]
        self.assertEqual(keyword_only, LOOP_KEYWORDS)
        for name in LOOP_KEYWORDS:
            self.assertIsNone(parameters[name].default)
        method = installed_stub_method("add_loop")
        self.assertEqual(
            [argument.arg for argument in method.args.kwonlyargs], LOOP_KEYWORDS
        )

    def test_add_loop_refuses_values_the_rust_setters_refuse(self) -> None:
        for keyword, value in (
            ("controlled_variable_units", 65_536),
            ("proportional_constant_units", 70_000),
            ("integral_constant_units", 65_536),
            ("derivative_constant_units", 65_536),
            ("priority_for_writing", 0),
            ("priority_for_writing", 17),
            ("priority_for_writing", 264),
        ):
            with self.subTest(keyword=keyword, value=value):
                with self.assertRaises(BacnetProtocolError) as raised:
                    make_server(**{keyword: value})
                assert_protocol_error(
                    self,
                    raised.exception,
                    ErrorClass.PROPERTY,
                    ErrorCode.VALUE_OUT_OF_RANGE,
                )


class LoopLiveServerTests(unittest.TestCase):
    def test_live_server_serves_settings_and_takes_the_measurement(self) -> None:
        asyncio.run(self._exercise_live_server())

    async def _exercise_live_server(self) -> None:
        server = make_server(
            controlled_variable_units=62,
            proportional_constant_units=98,
            priority_for_writing=10,
        )
        notifications: asyncio.Queue[Any] = asyncio.Queue()
        listener: asyncio.Task[None] | None = None

        await server.start()
        try:
            for property_id, expected in (
                (PropertyIdentifier.CONTROLLED_VARIABLE_UNITS, PropertyValue.enumerated(62)),
                (PropertyIdentifier.PROPORTIONAL_CONSTANT_UNITS, PropertyValue.enumerated(98)),
                (PropertyIdentifier.INTEGRAL_CONSTANT_UNITS, PropertyValue.enumerated(95)),
                (PropertyIdentifier.PRIORITY_FOR_WRITING, PropertyValue.unsigned(10)),
                (PropertyIdentifier.ACTION, PropertyValue.enumerated(0)),
            ):
                with self.subTest(property=property_id):
                    self.assertEqual(
                        await server.read_property(LOOP, property_id), expected
                    )

            address = await server.local_address()
            async with BACnetClient(
                interface="127.0.0.1",
                port=0,
                broadcast_address="127.0.0.1",
                apdu_timeout_ms=2_000,
            ) as client:
                iterator = await client.cov_notifications()

                async def collect_notifications() -> None:
                    async for notification in iterator:
                        notifications.put_nowait(notification)

                listener = asyncio.create_task(collect_notifications())
                await client.subscribe_cov(
                    address,
                    subscriber_process_identifier=1063,
                    monitored_object_identifier=LOOP,
                    confirmed=False,
                    lifetime=60,
                )
                initial = await asyncio.wait_for(
                    notifications.get(), timeout=NOTIFICATION_TIMEOUT
                )
                self.assertEqual(self._reported(initial, CVV), PropertyValue.real(0.0))

                # The measurement alone doesn't trigger a SubscribeCOV report...
                self.assertIsNone(
                    await server.set_controlled_variable_value_local(
                        LOOP, PropertyValue.real(21.5)
                    )
                )
                self.assertEqual(
                    await server.read_property(LOOP, CVV), PropertyValue.real(21.5)
                )
                await self._assert_silence(notifications)
                # ...and the next report carries it.
                await server.set_present_value_local(LOOP, PropertyValue.real(40.0))
                report = await asyncio.wait_for(
                    notifications.get(), timeout=NOTIFICATION_TIMEOUT
                )
                self.assertEqual(self._reported(report, CVV), PropertyValue.real(21.5))

                for value, code in (
                    (PropertyValue.unsigned(3), ErrorCode.INVALID_DATA_TYPE),
                    (PropertyValue.real(float("nan")), ErrorCode.VALUE_OUT_OF_RANGE),
                ):
                    with self.assertRaises(BacnetProtocolError) as raised:
                        await server.set_controlled_variable_value_local(LOOP, value)
                    assert_protocol_error(
                        self, raised.exception, ErrorClass.PROPERTY, code
                    )
                self.assertEqual(
                    await server.read_property(LOOP, CVV), PropertyValue.real(21.5)
                )
                for target, code in (
                    (AV, ErrorCode.OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED),
                    (ObjectIdentifier(ObjectType.LOOP, 9), ErrorCode.UNKNOWN_OBJECT),
                ):
                    with self.assertRaises(BacnetProtocolError) as raised:
                        await server.set_controlled_variable_value_local(
                            target, PropertyValue.real(1.0)
                        )
                    assert_protocol_error(
                        self, raised.exception, ErrorClass.OBJECT, code
                    )

                # Out_Of_Service doesn't block the measurement.
                await server.write_property_local(
                    LOOP,
                    PropertyIdentifier.OUT_OF_SERVICE,
                    PropertyValue.boolean(True),
                    source_object=None,
                )
                await asyncio.wait_for(notifications.get(), timeout=NOTIFICATION_TIMEOUT)
                await server.set_controlled_variable_value_local(
                    LOOP, PropertyValue.real(19.0)
                )
                self.assertEqual(
                    await server.read_property(LOOP, CVV), PropertyValue.real(19.0)
                )
                await self._assert_silence(notifications)
        finally:
            if listener is not None:
                listener.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await listener
            await server.stop()

    @staticmethod
    def _reported(notification: Any, property_id: Any) -> PropertyValue:
        assert notification.monitored_object_identifier == LOOP
        return next(
            item["value"]
            for item in notification.values
            if item["property_id"] == property_id
        )

    async def _assert_silence(self, notifications: asyncio.Queue[Any]) -> None:
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(notifications.get(), timeout=SILENCE_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
