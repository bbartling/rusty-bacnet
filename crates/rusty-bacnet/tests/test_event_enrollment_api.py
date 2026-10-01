"""Artifact tests for the typed Event Enrollment registration API (#930)."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path
from typing import Any

import rusty_bacnet
from rusty_bacnet import BACnetServer, EventType


def stub_method() -> ast.FunctionDef:
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
        if isinstance(node, ast.FunctionDef)
        and node.name == "add_event_enrollment"
    )


class EventEnrollmentApiTests(unittest.TestCase):
    def test_stub_annotates_event_type_as_the_enum(self) -> None:
        method = stub_method()
        stub_args = [*method.args.posonlyargs, *method.args.args]
        self.assertEqual(
            [arg.arg for arg in stub_args],
            ["self", "instance", "name", "event_type"],
        )
        annotation = stub_args[-1].annotation
        assert annotation is not None
        self.assertEqual(ast.unparse(annotation), "EventType")

    def test_event_type_is_optional_typed_and_rejects_ints(self) -> None:
        server = BACnetServer(
            device_instance=420_809,
            device_name="Event Enrollment Artifact Test",
            port=0,
        )
        server.add_event_enrollment(1, "EE-default")
        server.add_event_enrollment(2, "EE-typed", EventType.OUT_OF_RANGE)
        server.add_event_enrollment(3, "EE-proprietary", EventType.from_raw(600))

        invalid_call: Any = server.add_event_enrollment
        with self.assertRaises(TypeError):
            invalid_call(4, "EE-int", 5)


if __name__ == "__main__":
    unittest.main()
