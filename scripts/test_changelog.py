#!/usr/bin/env python3
"""Unit tests for changelog.py: python3 -m unittest discover -s scripts -p 'test_changelog.py'"""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

import changelog as cl

sys.path.insert(0, str(Path(__file__).with_name("release")))
import changelog_notes  # noqa: E402  (the release notes extractor reads what assemble writes)

NOTE = "Unreleased entries live in [`changelog.d/`](changelog.d/) until a release assembles them."

CHANGELOG = f"""# Changelog

Intro text.

## [Unreleased]

{NOTE}

## [1.0.0] - 2026-09-06

### Fixed

- An old fix.
"""

LINKED = CHANGELOG + """
[Unreleased]: https://example.invalid/r/compare/v1.0.0...HEAD
[1.0.0]: https://example.invalid/r/compare/v0.9.0...v1.0.0
"""


def fragment(section, *body):
    return "---\nsection: " + section + "\n---\n" + "\n".join(body) + "\n"


class Repo:
    """A temporary checkout with CHANGELOG.md and changelog.d/."""

    def __init__(self, changelog=CHANGELOG, fragments=None):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.changelog = self.root / "CHANGELOG.md"
        self.changelog.write_text(changelog, encoding="utf-8")
        self.dir = self.root / "changelog.d"
        self.dir.mkdir()
        (self.dir / "README.md").write_text("# Fragments\n\n- Not a fragment.\n", encoding="utf-8")
        for name, text in (fragments or {}).items():
            (self.dir / name).write_bytes(text.encode("utf-8"))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._tmp.cleanup()

    def run(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cl.main(["--root", str(self.root), *args])
        return code, out.getvalue(), err.getvalue()


class ParseFragmentTests(unittest.TestCase):
    def parse(self, name, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, name)
            path.write_bytes(text.encode("utf-8"))
            return cl.parse_fragment(path)

    def assert_rejected(self, name, text, message):
        with self.assertRaisesRegex(cl.ChangelogError, message):
            self.parse(name, text)

    def test_issue_and_slug_from_the_name(self):
        f = self.parse("1131-door-writes.md", fragment("Fixed", "- **Door (wire):** fixed.", "  More text."))
        self.assertEqual((f.issue, f.slug, f.section), (1131, "door-writes", "Fixed"))
        self.assertEqual(f.text, "- **Door (wire):** fixed.\n  More text.\n")

    def test_name_without_issue(self):
        f = self.parse("ci-cleanup.md", fragment("Changed", "- Tidied CI."))
        self.assertEqual((f.issue, f.slug), (None, "ci-cleanup"))

    def test_every_section_is_accepted(self):
        for section in cl.SECTIONS:
            with self.subTest(section=section):
                self.assertEqual(self.parse("1-x.md", fragment(section, "- Entry.")).section, section)

    def test_nested_bullets_and_paragraphs_stay_in_one_entry(self):
        body = ["- Lead.", "  - Nested one.", "    deeper.", "", "  A second paragraph."]
        self.assertEqual(self.parse("7-x.md", fragment("Added", *body)).text, "\n".join(body) + "\n")

    def test_blank_line_after_front_matter_is_allowed(self):
        self.assertEqual(self.parse("7-x.md", fragment("Added", "", "- Entry.")).text, "- Entry.\n")

    def test_bad_names(self):
        for name in ("1131_door.md", "1131-Door.md", "door.txt", "-door.md", "door-.md", "1131-.md"):
            with self.subTest(name=name):
                self.assert_rejected(name, fragment("Fixed", "- Entry."), "name it")

    def test_unknown_section(self):
        self.assert_rejected("1-x.md", fragment("Fixes", "- Entry."), "'Fixes' is not one of: Added")
        self.assert_rejected("1-x.md", fragment("fixed", "- Entry."), "is not one of")

    def test_front_matter_shape(self):
        self.assert_rejected("1-x.md", "- Entry.\n", "start with front matter")
        self.assert_rejected("1-x.md", "---\nsection: Fixed\n- Entry.\n", "no closing")
        self.assert_rejected("1-x.md", "---\nsection: Fixed\nissue: 1\n---\n- Entry.\n", "exactly one key")
        self.assert_rejected("1-x.md", "---\n---\n- Entry.\n", "exactly one key")

    def test_one_bullet_only(self):
        self.assert_rejected("1-x.md", fragment("Fixed", "- One.", "- Two."), r"1-x.md:5: indent continuation")
        self.assert_rejected("1-x.md", fragment("Fixed", "- One.", "not indented"), "indent continuation")
        self.assert_rejected("1-x.md", fragment("Fixed", "- One.", "", "- Two."), "indent continuation")
        self.assert_rejected("1-x.md", fragment("Fixed", "* Star."), "starting with '- '")
        self.assert_rejected("1-x.md", fragment("Fixed", "-   "), "trailing whitespace")
        self.assert_rejected("1-x.md", fragment("Fixed", "- "), "trailing whitespace")
        self.assert_rejected("1-x.md", fragment("Fixed", "-"), "starting with '- '")
        self.assert_rejected("1-x.md", "---\nsection: Fixed\n---\n", "no entry")

    def test_whitespace_and_line_endings(self):
        self.assert_rejected("1-x.md", fragment("Fixed", "- Entry. "), r"1-x.md:4: trailing whitespace")
        self.assert_rejected("1-x.md", fragment("Fixed", "- Entry.", ""), "blank line at the end")
        self.assert_rejected("1-x.md", fragment("Fixed", "- Entry.")[:-1], "end the file with a newline")
        self.assert_rejected("1-x.md", fragment("Fixed", "- Entry.").replace("\n", "\r\n"), "LF line endings")
        self.assert_rejected("1-x.md", fragment("Fixed", "- Entry.", "\tTabbed."), "indent continuation")


class CheckTests(unittest.TestCase):
    def test_valid_repository(self):
        with Repo(fragments={"5-a.md": fragment("Fixed", "- A.")}) as repo:
            code, out, err = repo.run("check")
            self.assertEqual((code, err), (0, ""))
            self.assertIn("1 fragment(s)", out)

    def test_readme_and_dotfiles_are_not_fragments(self):
        with Repo(fragments={".DS_Store": "junk"}) as repo:
            self.assertEqual(repo.run("check")[0], 0)

    def test_reports_every_bad_fragment(self):
        bad = {"1-a.md": fragment("Nope", "- A."), "2-b.md": "- B.\n", "notes.txt": "x\n"}
        with Repo(fragments=bad) as repo:
            code, _, err = repo.run("check")
            self.assertEqual(code, 1)
            for name in ("1-a.md", "2-b.md", "notes.txt"):
                self.assertIn(f"changelog.d/{name}", err)

    def test_subdirectory_is_rejected(self):
        with Repo() as repo:
            (repo.dir / "nested").mkdir()
            code, _, err = repo.run("check")
            self.assertEqual(code, 1)
            self.assertIn("changelog.d/nested", err)

    def test_entry_in_unreleased_fails(self):
        for added in ("- A direct edit.", "* Star bullet.", "1. Numbered.", "### Fixed"):
            with self.subTest(added=added):
                text = CHANGELOG.replace(NOTE, NOTE + "\n\n" + added)
                with Repo(changelog=text) as repo:
                    code, _, err = repo.run("check")
                    self.assertEqual(code, 1)
                    self.assertIn("CHANGELOG.md:9: [Unreleased] keeps only a note", err)

    def test_entries_in_released_sections_are_fine(self):
        with Repo() as repo:
            self.assertEqual(repo.run("check")[0], 0)

    def test_missing_unreleased_fails(self):
        with Repo(changelog=CHANGELOG.replace("## [Unreleased]", "## Unreleased")) as repo:
            code, _, err = repo.run("check")
            self.assertEqual(code, 1)
            self.assertIn("no '## [Unreleased]' section", err)

    def test_no_fragments_flag(self):
        with Repo(fragments={"5-a.md": fragment("Fixed", "- A.")}) as repo:
            code, _, err = repo.run("check", "--no-fragments")
            self.assertEqual(code, 1)
            self.assertIn("run changelog.py assemble before tagging", err)
        with Repo() as repo:
            self.assertEqual(repo.run("check", "--no-fragments")[0], 0)


ORDERING = {
    "1000-late.md": fragment("Fixed", "- Fix 1000."),
    "99-early.md": fragment("Fixed", "- Fix 99."),
    "99-another.md": fragment("Fixed", "- Fix 99, another."),
    "no-issue.md": fragment("Fixed", "- Fix without issue."),
    "200-migrate.md": fragment("Migration notes", "- Migrate."),
    "300-feature.md": fragment("Added", "- Feature 300.", "  continued."),
    "301-security.md": fragment("Security", "- Security 301."),
    "302-gone.md": fragment("Removed", "- Removed 302."),
    "303-old.md": fragment("Deprecated", "- Deprecated 303."),
    "304-change.md": fragment("Changed", "- Changed 304."),
}

ORDERED = """### Added

- Feature 300.
  continued.

### Changed

- Changed 304.

### Deprecated

- Deprecated 303.

### Removed

- Removed 302.

### Fixed

- Fix 99, another.

- Fix 99.

- Fix 1000.

- Fix without issue.

### Security

- Security 301.

### Migration notes

- Migrate.
"""


class PreviewTests(unittest.TestCase):
    def test_sections_in_order_and_entries_by_issue_then_slug(self):
        with Repo(fragments=ORDERING) as repo:
            code, out, err = repo.run("preview")
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(out, "## [Unreleased]\n\n" + ORDERED)

    def test_empty(self):
        with Repo() as repo:
            self.assertEqual(repo.run("preview")[1], "## [Unreleased]\n\nNo fragments in changelog.d/.\n")

    def test_bad_fragment_fails(self):
        with Repo(fragments={"1-a.md": "nope\n"}) as repo:
            code, out, err = repo.run("preview")
            self.assertEqual((code, out), (1, ""))
            self.assertIn("1-a.md", err)


class AssembleTests(unittest.TestCase):
    def test_writes_section_below_unreleased_and_deletes_fragments(self):
        with Repo(fragments=ORDERING) as repo:
            code, out, err = repo.run("assemble", "--version", "v1.1.0", "--date", "2026-10-02")
            self.assertEqual((code, err), (0, ""))
            self.assertIn("Assembled 10 fragment(s) into '## [1.1.0] - 2026-10-02'", out)
            text = repo.changelog.read_text(encoding="utf-8")
            expected = CHANGELOG.replace(
                "## [1.0.0]", "## [1.1.0] - 2026-10-02\n\n" + ORDERED + "\n## [1.0.0]"
            )
            self.assertEqual(text, expected)
            self.assertEqual(sorted(p.name for p in repo.dir.iterdir()), ["README.md"])
            # The release workflow's notes extractor finds the new section.
            self.assertEqual(changelog_notes.extract(text, "1.1.0"), ORDERED)
            # The result passes check, with nothing left waiting.
            self.assertEqual(repo.run("check", "--no-fragments")[0], 0)

    def test_default_date_is_today(self):
        with Repo(fragments={"1-a.md": fragment("Added", "- A.")}) as repo:
            self.assertEqual(repo.run("assemble", "--version", "1.1.0")[0], 0)
            today = cl.datetime.date.today().isoformat()
            self.assertIn(f"## [1.1.0] - {today}\n", repo.changelog.read_text(encoding="utf-8"))

    def test_unreleased_without_note_and_no_older_release(self):
        text = "# Changelog\n\n## [Unreleased]\n"
        with Repo(changelog=text, fragments={"1-a.md": fragment("Added", "- A.")}) as repo:
            self.assertEqual(repo.run("assemble", "--version", "0.1.0", "--date", "2026-10-02")[0], 0)
            self.assertEqual(
                repo.changelog.read_text(encoding="utf-8"),
                "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-10-02\n\n### Added\n\n- A.\n",
            )

    def test_updates_compare_links(self):
        with Repo(changelog=LINKED, fragments={"1-a.md": fragment("Added", "- A.")}) as repo:
            self.assertEqual(repo.run("assemble", "--version", "1.1.0", "--date", "2026-10-02")[0], 0)
            text = repo.changelog.read_text(encoding="utf-8")
            self.assertTrue(
                text.endswith(
                    "[Unreleased]: https://example.invalid/r/compare/v1.1.0...HEAD\n"
                    "[1.1.0]: https://example.invalid/r/compare/v1.0.0...v1.1.0\n"
                    "[1.0.0]: https://example.invalid/r/compare/v0.9.0...v1.0.0\n"
                ),
                text[-300:],
            )

    def test_output_leaves_changelog_and_fragments_alone(self):
        with Repo(fragments=ORDERING) as repo:
            out_path = repo.root / "assembled.md"
            code, _, _ = repo.run("assemble", "--version", "1.1.0", "--date", "2026-10-02", "--output", str(out_path))
            self.assertEqual(code, 0)
            self.assertEqual(repo.changelog.read_text(encoding="utf-8"), CHANGELOG)
            self.assertEqual(len(list(repo.dir.iterdir())), len(ORDERING) + 1)
            self.assertEqual(changelog_notes.extract(out_path.read_text(encoding="utf-8"), "1.1.0"), ORDERED)

    def test_refusals_change_nothing(self):
        cases = {
            "existing version": ({"1-a.md": fragment("Added", "- A.")}, ["--version", "1.0.0"], "already has"),
            "bad fragment": ({"1-a.md": fragment("Added", "- A."), "2-b.md": "x\n"}, ["--version", "1.1.0"], "2-b.md"),
            "no fragments": ({}, ["--version", "1.1.0"], "no fragments"),
        }
        for label, (fragments, args, message) in cases.items():
            with self.subTest(case=label), Repo(fragments=fragments) as repo:
                code, _, err = repo.run("assemble", *args, "--date", "2026-10-02")
                self.assertEqual(code, 1)
                self.assertIn(message, err)
                self.assertEqual(repo.changelog.read_text(encoding="utf-8"), CHANGELOG)
                self.assertEqual(len(list(repo.dir.iterdir())), len(fragments) + 1)

    def test_entry_in_unreleased_blocks_assembly(self):
        text = CHANGELOG.replace(NOTE, NOTE + "\n\n- A direct edit.")
        with Repo(changelog=text, fragments={"1-a.md": fragment("Added", "- A.")}) as repo:
            code, _, err = repo.run("assemble", "--version", "1.1.0")
            self.assertEqual(code, 1)
            self.assertIn("keeps only a note", err)
            self.assertEqual(repo.changelog.read_text(encoding="utf-8"), text)

    def test_allow_empty(self):
        with Repo() as repo:
            out_path = repo.root / "assembled.md"
            args = ["assemble", "--version", "1.1.0", "--date", "2026-10-02", "--output", str(out_path)]
            self.assertEqual(repo.run(*args, "--allow-empty")[0], 0)
            with self.assertRaises(changelog_notes.EmptySection):
                changelog_notes.extract(out_path.read_text(encoding="utf-8"), "1.1.0")

    def test_bad_version_or_date(self):
        for args in (["--version", "1.1"], ["--version", "1.1.0", "--date", "02-10-2026"],
                     ["--version", "1.1.0", "--date", "20261002"], ["--version", "1.1.0", "--date", "2026-02-30"]):
            with self.subTest(args=args), Repo(fragments={"1-a.md": fragment("Added", "- A.")}) as repo:
                with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                    repo.run("assemble", *args)


if __name__ == "__main__":
    unittest.main()
