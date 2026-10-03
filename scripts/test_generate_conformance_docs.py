"""Merge-safety test for the generated conformance docs (#1193).

Two PRs that each add a ledger row must change only row-local lines of the
generated docs. A shared aggregate line (a count or total) would be bumped by
both PRs and left stale by a textual merge."""

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
_spec = importlib.util.spec_from_file_location("gen_docs", SCRIPTS / "generate-conformance-docs.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def render(data: dict) -> dict[str, list[str]]:
    return {p.name: text.rstrip().split("\n") for p, text in gen.generated(data).items()}


def added_lines(base: list[str], new: list[str]) -> list[str]:
    old = set(base)
    return [line for line in new if line not in old]


class MergeSafety(unittest.TestCase):
    def test_two_added_rows_change_only_row_local_lines(self):
        base_data = gen.load_ledger()
        # Service text routes the row into the BIBB draft as well as the summary.
        template = copy.deepcopy(base_data["rows"][0])
        template["summary"] = gen.ledger_schema.summary(template) + " service"
        template.pop("requirement_summary", None)
        template["status"] = "unsupported-by-design"  # also routes into the PICS draft

        def synthetic(row_id: str) -> dict:
            row = copy.deepcopy(template)
            row["id"] = row_id
            return row

        row_a, row_b = synthetic("ZZ-SYNTH-A"), synthetic("ZZ-SYNTH-B")

        def with_rows(*rows):
            data = copy.deepcopy(base_data)
            data["rows"] = data["rows"] + list(rows)
            return render(data)

        base = with_rows()
        out_a, out_b, out_ab = with_rows(row_a), with_rows(row_b), with_rows(row_a, row_b)

        for name in base:
            touched = False
            for rid, out in (("ZZ-SYNTH-A", out_a), ("ZZ-SYNTH-B", out_b)):
                added = added_lines(base[name], out[name])
                touched = touched or bool(added)
                # Every changed line belongs to the new row; no base line is rewritten.
                self.assertEqual(len(out[name]) - len(base[name]), len(added), name)
                for line in added:
                    self.assertIn(rid, line, f"{name}: non-row-local line changed: {line}")
                self.assertEqual(added_lines(out[name], base[name]), [], name)
            self.assertTrue(touched, f"{name} did not show the synthetic rows")
            # A textual merge of both PRs equals regenerating with both rows.
            merged = set(base[name])
            merged |= set(added_lines(base[name], out_a[name]))
            merged |= set(added_lines(base[name], out_b[name]))
            self.assertEqual(set(out_ab[name]), merged, name)

    def test_counts_are_on_demand_only(self):
        table = gen.counts_table(gen.load_ledger())
        self.assertIn("| Priority |", table)
        self.assertIn("| Status |", table)
        summary = gen.OUTPUTS["support"].read_text(encoding="utf-8")
        self.assertNotIn("| Dimension |", summary)
        self.assertNotIn("## Counts", summary)


if __name__ == "__main__":
    unittest.main()
