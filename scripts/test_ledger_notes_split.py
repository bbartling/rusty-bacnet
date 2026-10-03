#!/usr/bin/env python3
"""Unit tests for ledger_notes_split.py:
python3 -m unittest discover -s scripts -p 'test_ledger_notes_split.py'"""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

import ledger_notes_split as lns

SCRIPTS = Path(__file__).resolve().parent

# Sentences of known length, so a test can tell where MIN_CHUNK closes an entry.
LONG = "This sentence is long enough on its own to close an entry, " + "padding " * 20 + "end."
assert len(LONG) >= lns.MIN_CHUNK


def ledger_text(notes_lines: list[str]) -> str:
    """A two-row ledger in the file's own layout; the second row has a key after notes."""
    return "\n".join(
        [
            "{",
            ' "standard": "S",',
            ' "rows": [',
            "  {",
            '   "id": "ROW-A",',
            '   "public_claims": [],',
            notes_lines[0],
            "  },",
            "  {",
            '   "id": "ROW-B",',
            notes_lines[1] + ",",
            '   "extra": {',
            '    "scope": "Not a notes key."',
            "   }",
            "  }",
            " ]",
            "}",
            "",
        ]
    )


class NotesTextTests(unittest.TestCase):
    def test_string_and_array_read_the_same(self):
        self.assertEqual(lns.notes_text("One. Two."), "One. Two.")
        self.assertEqual(lns.notes_text(["One.", "Two."]), "One. Two.")
        self.assertEqual(lns.notes_text([]), "")

    def test_other_shapes_are_rejected(self):
        for bad in (None, 7, {"text": "x"}, ["ok", 3]):
            with self.assertRaises(TypeError):
                lns.notes_text(bad)


class SplitTests(unittest.TestCase):
    def assertSplit(self, text):
        entries = lns.split_notes(text)
        self.assertEqual(" ".join(entries), text)
        return entries

    def test_short_note_stays_one_entry(self):
        self.assertEqual(self.assertSplit("Short. #12: also short."), ["Short. #12: also short."])
        self.assertEqual(lns.split_notes(""), [])

    def test_sentences_group_up_to_the_minimum(self):
        text = " ".join(["A short sentence."] * 30)
        entries = self.assertSplit(text)
        self.assertGreater(len(entries), 1)
        for entry in entries:
            self.assertGreaterEqual(len(entry), lns.MIN_CHUNK)

    def test_short_tail_joins_the_previous_entry(self):
        entries = self.assertSplit(f"{LONG} {LONG} Tail.")
        self.assertEqual(entries, [LONG, f"{LONG} Tail."])

    def test_issue_markers_open_an_entry(self):
        for marker in ("#1055:", "Refs #876:", "Refs #875 and #879:", "Refs #1025, following #999:"):
            with self.subTest(marker=marker):
                entries = self.assertSplit(f"Intro. {LONG} {marker} the next topic. Its tail.")
                self.assertEqual(entries, [f"Intro. {LONG}", f"{marker} the next topic. Its tail."])

    def test_marker_splits_even_after_a_short_paragraph(self):
        entries = self.assertSplit(f"Refs #800. #801: {LONG}")
        self.assertEqual(entries, ["Refs #800.", f"#801: {LONG}"])

    def test_an_issue_colon_later_in_a_sentence_is_no_marker(self):
        text = f"Intro. Not claimed for #1061: x. {LONG}"
        self.assertEqual(self.assertSplit(text), [text])

    def test_sentence_ends(self):
        self.assertEqual(
            lns.sentences("One ends. Two (see 5.) ends. #3: three. decode_npdu four. macOS five."),
            ["One ends.", "Two (see 5.) ends.", "#3: three.", "decode_npdu four.", "macOS five."],
        )

    def test_no_split_inside_a_sentence(self):
        cases = [
            "See PDF pp. 821-825 for it.",
            "Some forms (e.g. Foo) apply.",
            "Values in (...) stay rejected.",
            "The commandable! macro gained a rule.",
            "Read 0..=5 and Clause 12.36 has more.",
            "It ends. and a lower-case word follows.",
            "Two spaces.  Next sentence.",
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(lns.sentences(case), [case])
        self.assertEqual(lns.sentences(" Lead. Then."), [" Lead.", "Then."])

    def test_real_ledger_round_trips(self):
        data = json.loads(lns.LEDGER.read_text(encoding="utf-8"))
        for row in data["rows"]:
            text = lns.notes_text(row["notes"])
            self.assertEqual(" ".join(lns.split_notes(text)), text, row["id"])


class ConvertTests(unittest.TestCase):
    def test_rewrites_only_notes_lines_one_entry_per_line(self):
        first = f"Intro. {LONG} #12: the next topic."
        source = ledger_text([f'   "notes": "{first}"', '    "notes": "Short \\u00a7 note."'])
        text, converted = lns.convert(source)
        self.assertEqual(converted, 2)
        expected = ledger_text(
            [
                f'   "notes": [\n    "Intro. {LONG}",\n    "#12: the next topic."\n   ]',
                '    "notes": [\n     "Short \\u00a7 note."\n    ]',
            ]
        )
        self.assertEqual(text, expected)
        rows = json.loads(text)["rows"]
        self.assertEqual(lns.notes_text(rows[0]["notes"]), first)
        self.assertEqual(rows[1]["notes"], ["Short § note."])

    def test_rerun_is_a_no_op(self):
        source = ledger_text([f'   "notes": "{LONG} {LONG}"', '   "notes": "Short."'])
        once, _ = lns.convert(source)
        twice, converted = lns.convert(once)
        self.assertEqual((twice, converted), (once, 0))

    def test_refuses_a_notes_key_outside_a_row(self):
        source = ledger_text(['   "notes": "A."', '   "notes": "B."']).replace('"scope"', '"notes"')
        with self.assertRaises(ValueError):
            lns.convert(source)

    def test_real_ledger_converts_and_check_mode_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            path.write_text(lns.LEDGER.read_text(encoding="utf-8"), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                lns.main([str(path)])
                self.assertEqual(lns.main(["--check", str(path)]), 0)
                converted = path.read_text(encoding="utf-8")
                lns.main([str(path)])
            self.assertEqual(path.read_text(encoding="utf-8"), converted)
            data = json.loads(converted)
            data["rows"][0]["notes"] = lns.notes_text(data["rows"][0]["notes"])
            path.write_text(json.dumps(data), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(lns.main(["--check", str(path)]), 1)
            self.assertIn(data["rows"][0]["id"], out.getvalue())


class GeneratorTests(unittest.TestCase):
    def test_generated_docs_match_for_either_notes_form(self):
        spec = importlib.util.spec_from_file_location("gen", SCRIPTS / "generate-conformance-docs.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        data = json.loads(lns.LEDGER.read_text(encoding="utf-8"))
        joined = dict(data, rows=[dict(r, notes=lns.notes_text(r["notes"])) for r in data["rows"]])
        split = dict(data, rows=[dict(r, notes=lns.split_notes(r["notes"])) for r in joined["rows"]])
        self.assertEqual(gen.generated(joined), gen.generated(split))


if __name__ == "__main__":
    unittest.main()
