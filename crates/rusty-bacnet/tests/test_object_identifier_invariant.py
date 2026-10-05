"""Installed-binding controls for the 10-bit type / 22-bit instance invariant."""

import unittest

from rusty_bacnet import ObjectIdentifier, ObjectType


class ObjectIdentifierInvariantTests(unittest.TestCase):
    def test_over_width_types_are_selectors_but_not_identifiers(self) -> None:
        for raw in (1024, 2**32 - 1):
            with self.subTest(raw=raw):
                selector = ObjectType.from_raw(raw)
                self.assertEqual(selector.to_raw(), raw)
                with self.assertRaises(ValueError):
                    ObjectIdentifier(selector, 0)

    def test_over_width_instances_are_rejected(self) -> None:
        for instance in (2**22, 2**32 - 1):
            with self.subTest(instance=instance):
                with self.assertRaises(ValueError):
                    ObjectIdentifier(ObjectType.from_raw(1023), instance)

    def test_valid_proprietary_and_wildcard_identifiers_retain_identity(self) -> None:
        for raw in (128, 1023):
            for instance in (0, 2**22 - 2, 2**22 - 1):
                with self.subTest(raw=raw, instance=instance):
                    oid = ObjectIdentifier(ObjectType.from_raw(raw), instance)
                    self.assertEqual(oid.object_type.to_raw(), raw)
                    self.assertEqual(oid.instance, instance)
                    same = ObjectIdentifier(ObjectType.from_raw(raw), instance)
                    self.assertEqual(oid, same)
                    self.assertEqual(hash(oid), hash(same))
