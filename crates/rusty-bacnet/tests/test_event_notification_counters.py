"""Installed-wheel event telemetry: BACnetServer.event_notification_counters() (#1142)."""
import ast
import importlib.util
from pathlib import Path
import unittest

from rusty_bacnet import (
    BACnetServer, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
)

FIELDS = frozenset({
    "notification_class_missing",
    "recipient_list_unavailable",
    "recipient_list_invalid",
    "recipient_list_too_long",
    "confirmed_no_invoke_id",
    "confirmed_rejected",
    "confirmed_unanswered",
})


class EventNotificationCountersTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_transition_without_its_notification_class_is_counted(self):
        server = BACnetServer(503_807, interface="127.0.0.1", port=0,
                              broadcast_address="127.0.0.1")
        # Notification_Class defaults to 0, and no class 0 is added.
        server.add_analog_input(1, "Event counters")
        target = ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)
        with self.assertRaisesRegex(RuntimeError, "^server not started$"):
            await server.event_notification_counters()
        await server.start()
        try:
            expected = dict.fromkeys(FIELDS, 0)
            self.assertEqual(await server.event_notification_counters(), expected)
            for prop, value in [
                (PropertyIdentifier.HIGH_LIMIT, PropertyValue.real(1)),
                # high-limit-enable only
                (PropertyIdentifier.LIMIT_ENABLE, PropertyValue.bit_string(6, b"\x40")),
                # every transition enabled
                (PropertyIdentifier.EVENT_ENABLE, PropertyValue.bit_string(5, b"\xe0")),
            ]:
                await server.write_property_local(target, prop, value, source_object=None)
            self.assertEqual(await server.event_notification_counters(), expected)

            # NORMAL -> HIGH_LIMIT finds no Notification Class 0.
            await server.set_present_value_local(target, PropertyValue.real(2))
            expected["notification_class_missing"] += 1
            self.assertEqual(await server.event_notification_counters(), expected)
        finally:
            await server.stop()
        with self.assertRaisesRegex(RuntimeError, "^server not started$"):
            await server.event_notification_counters()

    def test_installed_stub_shape(self):
        spec = importlib.util.find_spec("rusty_bacnet")
        assert spec is not None and spec.origin is not None
        origin = Path(spec.origin)
        candidates = [origin.with_suffix(".pyi"), origin.parent / "rusty_bacnet.pyi"]
        stub = next(path for path in candidates if path.exists())
        classes = {node.name: node for node in ast.parse(stub.read_text()).body
                   if isinstance(node, ast.ClassDef)}
        fields = {node.target.id: ast.unparse(node.annotation)
                  for node in classes["EventNotificationCounters"].body
                  if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)}
        self.assertEqual(fields, dict.fromkeys(FIELDS, "int"))
        method = next(node for node in classes["BACnetServer"].body
                      if isinstance(node, ast.FunctionDef)
                      and node.name == "event_notification_counters")
        assert method.returns is not None
        self.assertEqual(ast.unparse(method.returns), "Awaitable[EventNotificationCounters]")


if __name__ == "__main__":
    unittest.main()
