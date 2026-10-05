"""PropertyValue lists nest at most 32 deep, and equal values hash alike (#1506).

32 is the decoder's nesting limit. A deeper PropertyValue.list raises
ValueError however it is called, by hand or by a pickle or copy rebuilding
a value, so reading, comparing, copying or dropping a value never recurses
past that depth. Numbers compare as numbers, so 0.0 and -0.0 are one value
and must hash as one; a NaN equals nothing, itself included.
"""

from __future__ import annotations

import copy
import math
import pickle
import struct
import time
import unittest
from typing import Any

from rusty_bacnet import PropertyValue

DEPTH = 32


def nested(depth: int) -> PropertyValue:
    """A null wrapped in `depth` lists."""
    value = PropertyValue.null()
    for _ in range(depth):
        value = PropertyValue.list([value])
    return value


def nesting_pickle(depth: int) -> bytes:
    """A protocol-2 pickle that calls PropertyValue.list `depth` times, each
    on a list holding the one before, starting from an empty list. Loading
    it pushes onto pickle's own stack, not Python's, so any depth loads as
    far as the constructor lets it."""
    get_list = (b"\x80\x02cbuiltins\ngetattr\ncrusty_bacnet\nPropertyValue\n"
                b"X\x04\x00\x00\x00list\x86Rq\x000")  # memo 0: PropertyValue.list
    open_level = b"h\x00]"  # PropertyValue.list, an empty list
    innermost = b"\x85R"  # call it on the empty list as it is
    close_level = b"a\x85R"  # append what's inside, then call it
    return get_list + open_level * depth + innermost + close_level * (depth - 1) + b"."


def copies(value: PropertyValue) -> list[PropertyValue]:
    """`value` through copy.copy, copy.deepcopy and every pickle protocol."""
    return [copy.copy(value), copy.deepcopy(value)] + [
        pickle.loads(pickle.dumps(value, protocol))
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1)
    ]


class ListDepthTests(unittest.TestCase):
    def test_a_list_32_deep_builds_reads_copies_and_pickles(self) -> None:
        deepest = nested(DEPTH)
        read = deepest.value
        for _ in range(DEPTH):
            self.assertIsInstance(read, list)
            self.assertEqual(len(read), 1)
            read = read[0]
        self.assertIsNone(read)
        for copied in copies(deepest):
            self.assertEqual(copied, deepest)
            self.assertEqual(hash(copied), hash(deepest))
            self.assertEqual(copied.value, deepest.value)
        # The crafted pickle below builds the same value at this depth.
        empty = PropertyValue.list([])
        for _ in range(DEPTH - 1):
            empty = PropertyValue.list([empty])
        self.assertEqual(pickle.loads(nesting_pickle(DEPTH)), empty)

    def test_a_list_33_deep_raises_value_error(self) -> None:
        deepest = nested(DEPTH)
        with self.assertRaisesRegex(ValueError, "lists nest at most 32 deep"):
            PropertyValue.list([deepest])
        # The deepest item counts, wherever it sits, at any level.
        deep_second = PropertyValue.list([PropertyValue.null(), nested(DEPTH - 1)])
        for items in ([PropertyValue.null(), deepest, PropertyValue.list([])],
                      [deep_second]):
            with self.assertRaises(ValueError):
                PropertyValue.list(items)
        # An empty list is one level.
        with self.assertRaises(ValueError):
            pickle.loads(nesting_pickle(DEPTH + 1))

    def test_a_10_000_deep_attempt_stops_at_the_cap(self) -> None:
        start = time.monotonic()
        value = PropertyValue.null()
        built = 0
        with self.assertRaises(ValueError):
            for _ in range(10_000):
                value = PropertyValue.list([value])
                built += 1
        self.assertEqual(built, DEPTH)
        with self.assertRaises(ValueError):
            pickle.loads(nesting_pickle(10_000))
        self.assertLess(time.monotonic() - start, 5.0)


def float_samples() -> list[float]:
    """Both zeros, NaNs of either sign and another payload, and others."""
    nan = float("nan")
    other_nan = struct.unpack("<d", struct.pack("<Q", 0x7FF8_0000_0000_0001))[0]
    return [0.0, -0.0, nan, -nan, other_nan, 1.0, -1.0, 1.1, math.inf, -math.inf]


class HashTests(unittest.TestCase):
    def assert_hash_follows_equality(self, values: list[Any]) -> None:
        # Inside a list too, which compares and hashes item by item.
        values = values + [PropertyValue.list([value]) for value in values]
        for a in values:
            for b in values:
                if a == b:
                    with self.subTest(a=repr(a), b=repr(b)):
                        self.assertEqual(hash(a), hash(b))

    def test_equal_numbers_hash_alike(self) -> None:
        samples = {
            "real": [PropertyValue.real(f) for f in float_samples()],
            "double": [PropertyValue.double(f) for f in float_samples()],
            "unsigned": [PropertyValue.unsigned(n) for n in (0, 1, 2**64 - 1)],
            "signed": [PropertyValue.signed(n) for n in (0, -1, 1, -(2**31))],
            "enumerated": [PropertyValue.enumerated(n) for n in (0, 1, 2**32 - 1)],
        }
        for tag, values in samples.items():
            with self.subTest(tag=tag):
                self.assertEqual({value.tag for value in values}, {tag})
                self.assert_hash_follows_equality(values)

    def test_signed_zero_is_one_value(self) -> None:
        for make in (PropertyValue.real, PropertyValue.double):
            with self.subTest(tag=make(0.0).tag):
                self.assertEqual(make(0.0), make(-0.0))
                self.assertEqual(hash(make(0.0)), hash(make(-0.0)))
                self.assertEqual(len({make(0.0), make(-0.0)}), 1)
                self.assertEqual(len({PropertyValue.list([make(0.0)]),
                                      PropertyValue.list([make(-0.0)])}), 1)


if __name__ == "__main__":
    unittest.main()
