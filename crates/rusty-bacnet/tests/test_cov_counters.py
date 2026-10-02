"""Installed-wheel COV telemetry: BACnetServer.cov_counters() (#1084)."""
import ast
import asyncio
import contextlib
import importlib.util
from pathlib import Path
import unittest

from rusty_bacnet import (
    BACnetClient, BACnetServer, BacnetProtocolError, ErrorClass, ErrorCode,
    ObjectIdentifier, ObjectType, PropertyValue,
)

FIELDS = frozenset({
    "subscriptions_active",
    "subscriptions_created",
    "subscriptions_rejected_quota",
    "subscriptions_rejected_capacity",
    "subscriptions_rejected_indefinite",
    "subscriptions_cancelled",
    "subscriptions_purged",
    "notifications_sent",
    "notifications_confirmed",
    "notifications_unconfirmed",
    "notification_bytes_sent",
    "notifications_throttled_fanout",
    "notifications_throttled_peer",
    "timed_changes_dropped",
    "untimed_references_oversized",
})

# CovPolicy::default() admits 16 indefinite subscriptions per peer.
INDEFINITE_PER_PEER = 16


class CovCountersTests(unittest.IsolatedAsyncioTestCase):
    async def test_subscriptions_notifications_rejection_and_cancel_move_their_fields(self):
        server = BACnetServer(503_806, interface="127.0.0.1", port=0,
                              broadcast_address="127.0.0.1")
        server.add_analog_input(1, "COV counters", present_value=10.0)
        target = ObjectIdentifier(ObjectType.ANALOG_INPUT, 1)
        with self.assertRaisesRegex(RuntimeError, "^server not started$"):
            await server.cov_counters()
        await server.start()
        try:
            expected = dict.fromkeys(FIELDS, 0)
            self.assertEqual(await server.cov_counters(), expected)
            async with BACnetClient(interface="127.0.0.1", port=0,
                                    broadcast_address="127.0.0.1", apdu_timeout_ms=2000) as client:
                notifications = asyncio.Queue()
                iterator = await client.cov_notifications()

                async def collect():
                    async for notification in iterator:
                        notifications.put_nowait(notification)

                listener = asyncio.create_task(collect())
                try:
                    address = await server.local_address()

                    async def sample(**moved):
                        """Wait for one notification, then check the fields
                        that moved; the byte total only has to grow."""
                        await asyncio.wait_for(notifications.get(), 2)
                        counters = await server.cov_counters()
                        self.assertGreater(counters["notification_bytes_sent"],
                                           expected["notification_bytes_sent"])
                        expected["notification_bytes_sent"] = counters["notification_bytes_sent"]
                        for field, step in moved.items():
                            expected[field] += step
                        self.assertEqual(counters, expected)

                    # An accepted subscription sends its initial notification.
                    await client.subscribe_cov(address, 1, target, confirmed=False, lifetime=60)
                    await sample(subscriptions_created=1, subscriptions_active=1,
                                 notifications_sent=1, notifications_unconfirmed=1)
                    await client.subscribe_cov(address, 2, target, confirmed=True, lifetime=60)
                    await sample(subscriptions_created=1, subscriptions_active=1,
                                 notifications_sent=1, notifications_confirmed=1)

                    # A change notifies both subscribers.
                    await server.set_present_value_local(target, PropertyValue.real(15.0))
                    await asyncio.wait_for(notifications.get(), 2)
                    await sample(notifications_sent=2, notifications_unconfirmed=1,
                                 notifications_confirmed=1)

                    # The peer's indefinite quota admits 16; the next is refused.
                    for process_id in range(3, 3 + INDEFINITE_PER_PEER):
                        await client.subscribe_cov(address, process_id, target, confirmed=False)
                        await sample(subscriptions_created=1, subscriptions_active=1,
                                     notifications_sent=1, notifications_unconfirmed=1)
                    with self.assertRaises(BacnetProtocolError) as refused:
                        await client.subscribe_cov(address, 99, target, confirmed=False)
                    self.assertEqual(refused.exception.error_class, ErrorClass.RESOURCES.to_raw())
                    self.assertEqual(refused.exception.error_code,
                                     ErrorCode.NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw())
                    expected["subscriptions_rejected_indefinite"] += 1
                    self.assertEqual(await server.cov_counters(), expected)

                    await client.unsubscribe_cov(address, 1, target)
                    expected["subscriptions_cancelled"] += 1
                    expected["subscriptions_active"] -= 1
                    self.assertEqual(await server.cov_counters(), expected)
                finally:
                    listener.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await listener
        finally:
            await server.stop()
        with self.assertRaisesRegex(RuntimeError, "^server not started$"):
            await server.cov_counters()

    def test_installed_stub_shape(self):
        spec = importlib.util.find_spec("rusty_bacnet")
        assert spec is not None and spec.origin is not None
        origin = Path(spec.origin)
        candidates = [origin.with_suffix(".pyi"), origin.parent / "rusty_bacnet.pyi"]
        stub = next(path for path in candidates if path.exists())
        classes = {node.name: node for node in ast.parse(stub.read_text()).body
                   if isinstance(node, ast.ClassDef)}
        fields = {node.target.id: ast.unparse(node.annotation)
                  for node in classes["CovCounters"].body
                  if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)}
        self.assertEqual(fields, dict.fromkeys(FIELDS, "int"))
        method = next(node for node in classes["BACnetServer"].body
                      if isinstance(node, ast.FunctionDef) and node.name == "cov_counters")
        assert method.returns is not None
        self.assertEqual(ast.unparse(method.returns), "Awaitable[CovCounters]")


if __name__ == "__main__":
    unittest.main()
