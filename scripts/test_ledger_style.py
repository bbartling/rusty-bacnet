#!/usr/bin/env python3
"""Unit tests for check_ledger_style.py and ledger_schema.py:
python3 -m unittest discover -s scripts -p 'test_ledger_style.py'"""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import check_ledger_anchors as cla
import check_ledger_style as cls
import ledger_schema

GOOD = {
    "id": "BACNET-X-GOOD",
    "standard_anchor": "Clause 15.5; Table 12-13",
    "priority": "P1",
    "summary": "ReadProperty answers every property of the local Device with its stored value.",
    "status": "implementation-present-needs-negative-tests",
    "code_anchors": ["scripts/check_ledger_style.py"],
    "positive_tests": [],
    "negative_tests": [],
    "benchmarks": [],
    "public_claims": [],
    "notes": ["A wildcard Device instance reads as the local Device."],
    "gaps": ["#1234: no negative test for an unknown property yet.", "Segmented replies are untested (no issue)"],
}


def rules(row: dict, pending: bool = False) -> list[str]:
    return [p.rule for p in cls.row_problems(row, pending)]


def edit(**changes) -> dict:
    row = copy.deepcopy(GOOD)
    for key, value in changes.items():
        if value is None:
            row.pop(key, None)
        else:
            row[key] = value
    return row


class RowRules(unittest.TestCase):
    def test_good_row_passes(self):
        self.assertEqual(rules(GOOD), [])

    def test_each_broken_rule_is_reported(self):
        cases = {
            "keys": [edit(extra_policy="x"), edit(requirement_summary="old")],
            "summary": [edit(summary=None), edit(summary=""), edit(summary="x" * 201)],
            "notes-shape": [edit(notes="one string"), edit(notes=None), edit(notes=[" padded"]), edit(notes=[""])],
            "notes-cap": [edit(notes=["n"] * 6), edit(notes=["x" * 241])],
            "gaps-shape": [edit(gaps="#1: one string"), edit(gaps=[3])],
            "gaps-required": [edit(gaps=None), edit(gaps=[])],
            "gap-cap": [edit(gaps=["#1: " + "x" * 197])],
            "gap-ref": [edit(gaps=["No issue named here."]), edit(gaps=["#12 lacks its colon."]), edit(gaps=["Ends wrong (no issue)."])],
            "issue-outside-gaps": [edit(summary="Reads work (#12)."), edit(notes=["See #99."]), edit(standard_anchor="Clause 5 #4")],
            "anchor-cap": [edit(standard_anchor="Clause 12.1; " * 9)],
            "anchor-page": [edit(standard_anchor=a) for a in ("Clause 12.24 (p. 309)", "Clause 15.8 (pp. 745-750)", "Clause 12.63, page 619", "Clause 12.56 printed551", "Clause 15 (PDF753)")],
            "banned-phrase": [
                edit(notes=["Split child of the old row."]),
                edit(notes=["Before, the stack dropped it."]),
                edit(summary="Reads work while the issue remains open."),
                edit(notes=["Status is open/partial."]),
                edit(notes=["Added in the third tranche."]),
                edit(summary="The device shall answer reads."),
                edit(gaps=["#5: the hub must reply (no issue)"]),
            ],
        }
        for rule, rows in cases.items():
            for row in rows:
                with self.subTest(rule=rule, row=row):
                    self.assertIn(rule, rules(row))

    def test_supported_and_by_design_rows_need_no_gaps(self):
        for status in sorted(ledger_schema.NO_GAP_STATUSES):
            self.assertEqual(rules(edit(status=status, gaps=None)), [], status)

    def test_gap_forms(self):
        for gap in ("#7: open work.", "Out of scope here (not planned)", "No tracker entry yet (no issue)"):
            self.assertEqual(rules(edit(gaps=[gap])), [], gap)

    def test_code_spans_and_identifiers_are_not_banned_phrases(self):
        row = edit(notes=["The `must_understand` flag and `ShallowCopy` stay local.", "Musty and mustard are fine."])
        self.assertEqual(rules(row), [])

    def test_pending_row_checks_only_keys_and_notes_shape(self):
        legacy = edit(summary=None, gaps=None, requirement_summary="Old " * 80, standard_anchor="Clause 1 (p. 3) #4")
        legacy["zero_limit_admission"] = "Kept until a batch folds it."
        legacy["evidence"] = ["Temporary table cell."]
        self.assertEqual(rules(legacy, pending=True), [])
        self.assertEqual(rules(edit(brand_new_key=1), pending=True), ["keys"])
        self.assertEqual(rules(edit(notes="one string"), pending=True), ["notes-shape"])

    def test_legacy_keys_fail_once_a_row_leaves_pending(self):
        for key in ("evidence", "requirement_summary", "hub_unknown_transit"):
            problems = cls.row_problems(edit(**{key: ["x"]}))
            self.assertEqual([p.rule for p in problems], ["keys"], key)
            self.assertIn("pending", problems[0].detail)


class LedgerChecks(unittest.TestCase):
    def test_current_ledger_passes_with_its_pending_list(self):
        data = json.loads(cls.LEDGER.read_text(encoding="utf-8"))
        self.assertEqual([str(p) for p in cls.problems(data, cls.load_pending())], [])

    def test_pending_list_lines_must_name_rows_once(self):
        data = {"rows": [GOOD]}
        found = cls.problems(data, ["BACNET-X-GOOD", "BACNET-X-GOOD", "BACNET-GONE"])
        self.assertEqual([(p.row, p.rule) for p in found], [("BACNET-X-GOOD", "pending"), ("BACNET-GONE", "pending")])

    def test_pending_file_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pending.txt"
            path.write_text("# header\n\nROW-A\nROW-B  # trailing note\n", encoding="utf-8")
            self.assertEqual(cls.load_pending(path), ["ROW-A", "ROW-B"])
            self.assertEqual(cls.load_pending(Path(tmp) / "absent.txt"), [])

    def test_failures_print_rule_and_fix(self):
        data = {"rows": [edit(gaps=["No issue named here."])]}
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(out):
            code = cls.check(data, Path(tmp) / "none.txt")
        self.assertEqual(code, 1)
        text = out.getvalue()
        self.assertIn("BACNET-X-GOOD: [gap-ref]", text)
        self.assertIn("fix: " + cls.HINTS["gap-ref"], text)

    def test_readme_example_row_passes_and_resolves(self):
        readme = (cls.ROOT / "docs" / "conformance" / "README.md").read_text(encoding="utf-8")
        row = json.loads(readme.split("```json\n", 1)[1].split("```", 1)[0])
        self.assertEqual([str(p) for p in cls.row_problems(row)], [])
        for field in ("positive_tests", "negative_tests"):
            for anchor in row[field]:
                self.assertIsNone(cla.resolve(anchor), anchor)
        for anchor in row["code_anchors"] + row["benchmarks"]:
            self.assertIsNone(cla.resolve_path(anchor), anchor)
        for claim in row["public_claims"]:
            self.assertIsNone(cla.resolve_claim(claim), claim)

    def test_every_reported_rule_has_a_hint(self):
        data = json.loads(cls.LEDGER.read_text(encoding="utf-8"))
        for problem in cls.problems(data, []):
            self.assertIn(problem.rule, cls.HINTS)


class SchemaReaders(unittest.TestCase):
    def test_summary_falls_back_to_requirement_summary(self):
        self.assertEqual(ledger_schema.summary({"summary": "New."}), "New.")
        self.assertEqual(ledger_schema.summary({"requirement_summary": "Old."}), "Old.")
        self.assertEqual(ledger_schema.summary({"summary": "New.", "requirement_summary": "Old."}), "New.")
        self.assertEqual(ledger_schema.summary({}), "")

    def test_missing_gaps_read_as_empty(self):
        self.assertEqual(ledger_schema.gaps({}), [])
        self.assertEqual(ledger_schema.gaps({"gaps": ["#1: x."]}), ["#1: x."])
        with self.assertRaises(TypeError):
            ledger_schema.gaps({"id": "X", "gaps": "#1: x."})

    def test_notes_read_as_their_entries_joined(self):
        self.assertEqual(ledger_schema.notes_text({"notes": ["One.", "Two."]}), "One. Two.")
        self.assertEqual(ledger_schema.notes_text({"notes": []}), "")
        for bad in ("One. Two.", ["One.", 2], None):
            with self.assertRaises(TypeError):
                ledger_schema.notes_text({"id": "X", "notes": bad})


if __name__ == "__main__":
    unittest.main()
