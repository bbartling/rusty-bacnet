#!/usr/bin/env python3
"""Unit tests for the code and benchmark anchors of check_ledger_anchors.py:
python3 -m unittest discover -s scripts -p 'test_ledger_anchors.py'"""

import json
import tempfile
import unittest
from pathlib import Path

import check_ledger_anchors as cla


class PathAnchors(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for rel, text in {
            "crates/a-one/src/hub.rs": "pub struct Hub;\nimpl Hub { pub fn start() {} }\n",
            "crates/a-two/src/lib.rs": "mod hub;\n",
            "benchmarks/benches/bip.rs": "fn main() {}\n",
        }.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def resolve(self, anchor: str):
        return cla.resolve_path(anchor, self.root)

    def test_existing_paths_globs_and_names_resolve(self):
        for anchor in (
            "crates/a-one/src/hub.rs",
            "crates/a-one/src",
            "crates/a-*/src",
            "crates/a-one/src/hub.rs::Hub::start",
            "crates/a-*/src/*.rs::Hub",
            "crates/a-{one,two}/src",
            "benchmarks/benches/bip.rs (round trip)",
        ):
            self.assertIsNone(self.resolve(anchor), anchor)

    def test_dead_paths_globs_and_names_fail(self):
        for anchor, why in (
            ("crates/a-one/src/gone.rs", "file does not exist"),
            ("crates/b-*/src", "glob matches no file"),
            ("crates/a-one/src/hub.rs::stop", "`stop` does not appear in the file"),
            ("crates/a-one/src/hub.rs::Hu", "`Hu` does not appear in the file"),
            ("crates/a-{one,three}/src", "file does not exist"),
        ):
            self.assertEqual(self.resolve(anchor), why, anchor)

    def test_stale_paths_reads_code_anchors_and_benchmarks(self):
        data = {
            "rows": [
                {"id": "R1", "code_anchors": ["crates/a-one/src/hub.rs", "crates/gone.rs"], "benchmarks": []},
                {"id": "R2", "code_anchors": [], "benchmarks": ["benchmarks/benches/gone.rs"]},
            ]
        }
        self.assertEqual(
            [(row, anchor) for row, anchor, _ in cla.stale_paths(data, self.root)],
            [("R1", "crates/gone.rs"), ("R2", "benchmarks/benches/gone.rs")],
        )

    def test_self_test_rejects_its_fixtures(self):
        self.assertEqual(cla.self_test(), [])

    def test_current_ledger_code_and_benchmark_anchors_resolve(self):
        data = json.loads(cla.LEDGER.read_text(encoding="utf-8"))
        self.assertEqual(cla.stale_paths(data), [])


if __name__ == "__main__":
    unittest.main()
