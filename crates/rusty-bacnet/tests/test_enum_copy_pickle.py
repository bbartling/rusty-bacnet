"""Every generated enum class copies and pickles (#1456).

The classes py_bacnet_enum! generates live in the rusty_bacnet module and
rebuild a value through from_raw(to_raw()), so copy.copy, copy.deepcopy and
pickle give back an equal value of the same class, for named constants and
raw values with no name alike.
"""

from __future__ import annotations

import copy
import pickle
import unittest

import rusty_bacnet
from rusty_bacnet import EnableDisable


def enum_classes() -> dict[str, type]:
    """Every generated enum class, found at runtime as the stub parity test
    finds them, so a new one is covered without listing it here."""
    return {
        name: cls
        for name, cls in vars(rusty_bacnet).items()
        if isinstance(cls, type)
        and callable(getattr(cls, "from_raw", None))
        and callable(getattr(cls, "to_raw", None))
    }


class EnumCopyPickleTests(unittest.TestCase):
    def test_every_enum_class_copies_and_pickles(self) -> None:
        classes = enum_classes()
        self.assertGreaterEqual(len(classes), 15)
        for name, cls in classes.items():
            with self.subTest(enum=name):
                self.assertEqual(cls.__module__, "rusty_bacnet")
                registered = [value for value in vars(cls).values() if isinstance(value, cls)]
                self.assertTrue(registered)
                # Every named constant, and a raw value no constant names.
                for value in [*registered, cls.from_raw(200)]:
                    copies = [copy.copy(value), copy.deepcopy(value)]
                    copies += [
                        pickle.loads(pickle.dumps(value, protocol))
                        for protocol in range(pickle.HIGHEST_PROTOCOL + 1)
                    ]
                    for copied in copies:
                        self.assertIs(type(copied), cls)
                        self.assertEqual(copied, value)
                        self.assertEqual(copied.to_raw(), value.to_raw())
                        self.assertEqual(hash(copied), hash(value))
                        self.assertEqual(repr(copied), repr(value))

    def test_a_pickle_names_the_module_and_from_raw(self) -> None:
        dumped = pickle.dumps(EnableDisable.DISABLE_INITIATION)
        self.assertIn(b"rusty_bacnet", dumped)
        self.assertIn(b"from_raw", dumped)
        # Containers holding enums deep-copy and pickle too.
        state = {"comm": [EnableDisable.ENABLE, EnableDisable.DISABLE_INITIATION]}
        self.assertEqual(copy.deepcopy(state), state)
        self.assertEqual(pickle.loads(pickle.dumps(state)), state)


if __name__ == "__main__":
    unittest.main()
