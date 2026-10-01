#!/usr/bin/env python3
"""Unit tests for changelog_notes.py: python3 -m unittest discover -s scripts/release"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import changelog_notes as notes

SAMPLE = """# Changelog

Intro text.

## [Unreleased]

### Added

- Pending feature.

## [1.2.0] - 2026-09-06

### Fixed

- A fix.

```markdown
## [9.9.9]
not a heading inside a fence
```

- After the fence.

## [1.1.0]

- Older.

## [1.0.0]

## [0.9.0]

- Oldest.
"""


class ExtractTests(unittest.TestCase):
    def test_versioned_section_excludes_heading_and_stops_at_next(self):
        body = notes.extract(SAMPLE, "1.2.0")
        self.assertTrue(body.startswith("### Fixed\n"))
        self.assertIn("- After the fence.", body)
        self.assertNotIn("## [1.2.0]", body)
        self.assertNotIn("Older", body)
        self.assertTrue(body.endswith("- After the fence.\n"))

    def test_heading_inside_fence_is_not_a_boundary_or_match(self):
        self.assertIn("## [9.9.9]", notes.extract(SAMPLE, "1.2.0"))
        with self.assertRaisesRegex(notes.NotesError, r"no '## \[9\.9\.9\]'"):
            notes.extract(SAMPLE, "9.9.9")

    def test_unreleased_is_case_insensitive(self):
        self.assertEqual(notes.extract(SAMPLE, "unreleased"), "### Added\n\n- Pending feature.\n")

    def test_heading_without_date(self):
        self.assertEqual(notes.extract(SAMPLE, "1.1.0"), "- Older.\n")

    def test_last_section_runs_to_end(self):
        self.assertEqual(notes.extract(SAMPLE, "0.9.0"), "- Oldest.\n")

    def test_missing_section(self):
        with self.assertRaisesRegex(notes.NotesError, "no '## \\[2.0.0\\]' section"):
            notes.extract(SAMPLE, "2.0.0")

    def test_empty_section(self):
        with self.assertRaisesRegex(notes.NotesError, "empty"):
            notes.extract(SAMPLE, "1.0.0")

    def test_prefix_version_is_not_a_match(self):
        with self.assertRaises(notes.NotesError):
            notes.extract(SAMPLE, "1.2")


class TruncateTests(unittest.TestCase):
    URL = "https://example.invalid/CHANGELOG.md"

    def test_short_body_is_unchanged(self):
        self.assertEqual(notes.truncate("abc\n", 10, self.URL), "abc\n")

    def test_long_body_cuts_at_paragraph_and_links(self):
        body = "".join(f"- item {i}\n\n" for i in range(200))
        out = notes.truncate(body, 500, self.URL)
        self.assertLessEqual(len(out), 500)
        self.assertIn(self.URL, out)
        kept = out.split("\n_These notes")[0]
        self.assertTrue(kept.rstrip("\n").endswith(tuple(f"- item {i}" for i in range(200))))
        self.assertTrue(body.startswith(kept.rstrip("\n")))

    def test_no_room_for_footer(self):
        with self.assertRaises(notes.NotesError):
            notes.truncate("x" * 100, 10, self.URL)

    def test_never_longer_than_max_chars(self):
        bodies = {
            "paragraphs": "".join(f"- item {i}\n\n" for i in range(100)),
            "lines": "".join(f"- item {i}\n" for i in range(100)),
            "one line": "x" * 2000,
            "fenced": "intro\n\n```text\n" + "".join(f"line {i}\n" for i in range(200)) + "```\n",
        }
        for label, body in bodies.items():
            for max_chars in range(110, 600, 7):
                with self.subTest(body=label, max_chars=max_chars):
                    out = notes.truncate(body, max_chars, self.URL)
                    self.assertLessEqual(len(out), max_chars)
                    self.assertTrue(out.endswith(f"[CHANGELOG.md]({self.URL})._\n"))

    def test_cut_inside_a_code_block_closes_it(self):
        body = "### Changed\n````rust\n" + "".join(f"let x{i} = {i};\n" for i in range(100)) + "````\n\nAfter.\n"
        out = notes.truncate(body, 400, self.URL)
        self.assertLessEqual(len(out), 400)
        kept = out.split("\n_These notes")[0]
        self.assertTrue(kept.endswith("\n````\n"), kept[-40:])
        self.assertIsNone(notes.open_fence(kept))

    def test_open_fence(self):
        self.assertEqual(notes.open_fence("a\n```python\nx\n"), "```")
        self.assertIsNone(notes.open_fence("```\nx\n```\n"))
        # A shorter or different run doesn't close the block; an info string never closes.
        self.assertEqual(notes.open_fence("````\n```\n~~~~\n```` x\n"), "````")
        self.assertIsNone(notes.open_fence("~~~\n```\n~~~~\n"))


class MainTests(unittest.TestCase):
    def run_main(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "CHANGELOG.md")
            path.write_text(SAMPLE, encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = notes.main(["--changelog", str(path), *args])
            return code, out.getvalue(), err.getvalue()

    def test_version_with_v_prefix(self):
        code, out, _ = self.run_main("--version", "v1.1.0")
        self.assertEqual((code, out), (0, "- Older.\n"))

    def test_missing_version_fails_with_message(self):
        code, out, err = self.run_main("--version", "3.0.0")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("no '## [3.0.0]' section", err)

    def test_empty_section_fails_unless_allowed(self):
        code, _, err = self.run_main("--version", "1.0.0")
        self.assertEqual(code, 1)
        self.assertIn("empty", err)
        code, out, _ = self.run_main("--version", "1.0.0", "--allow-empty")
        self.assertEqual((code, out), (0, "No changes are listed under 1.0.0 yet.\n"))
        code, _, err = self.run_main("--version", "3.0.0", "--allow-empty")
        self.assertEqual(code, 1)
        self.assertIn("no '## [3.0.0]' section", err)

    def test_max_chars_needs_url(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.run_main("--unreleased", "--max-chars", "100")


if __name__ == "__main__":
    unittest.main()
