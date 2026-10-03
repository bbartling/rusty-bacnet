#!/usr/bin/env python3
"""Unit tests for changelog.py: python3 -m unittest discover -s scripts -p 'test_changelog.py'"""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import changelog as cl
import changelog_pin_commits as pin_commits

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

    def test_wrapped_lines_stay_in_one_entry(self):
        body = ["- Lead sentence that wraps", "  onto a second line (#7)."]
        self.assertEqual(self.parse("7-x.md", fragment("Added", *body)).text, "\n".join(body) + "\n")

    def test_nested_bullet_is_rejected(self):
        for nested in ("  - Nested.", "  * Nested.", "  + Nested.", "  1. Numbered.", "    - Deeper."):
            with self.subTest(nested=nested):
                self.assert_rejected("7-x.md", fragment("Added", "- Lead.", nested), r"7-x.md:5: no nested bullets")

    def test_second_paragraph_is_rejected(self):
        self.assert_rejected("7-x.md", fragment("Added", "- Lead.", "", "  More."), r"7-x.md:5: keep the entry to one paragraph")

    def test_length_cap(self):
        for section, cap in (("Fixed", cl.ENTRY_CAP), ("Migration notes", cl.MIGRATION_CAP)):
            with self.subTest(section=section):
                # A wrapped line's break and indent count as one space.
                lines = ["- " + "a" * (cap - 10), "  " + "b" * 9]
                self.assertEqual(cl.entry_length("\n".join(lines)), cap)
                self.parse("7-x.md", fragment(section, *lines))
                longer = [lines[0] + "a", lines[1]]
                self.assert_rejected("7-x.md", fragment(section, *longer), rf"is {cap + 1} characters; keep it to {cap}")

    def test_link_targets_and_wrapping_do_not_count(self):
        entry = "- See [the ledger](docs/conformance/" + "a" * 400 + ".md#anchor)\n  for detail (#7)."
        self.assertEqual(cl.entry_length(entry), len("See the ledger for detail (#7)."))
        self.parse("7-x.md", fragment("Fixed", *entry.split("\n")))

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
        self.assert_rejected("1-x.md", "---\nsection: Fixed\nissue: 1\n---\n- Entry.\n", "optionally 'commit: <sha>'")
        self.assert_rejected("1-x.md", "---\n---\n- Entry.\n", "optionally 'commit: <sha>'")

    def test_one_bullet_only(self):
        self.assert_rejected("1-x.md", fragment("Fixed", "- One.", "- Two."), r"1-x.md:5: indent continuation")
        self.assert_rejected("1-x.md", fragment("Fixed", "- One.", "not indented"), "indent continuation")
        self.assert_rejected("1-x.md", fragment("Fixed", "- One.", "", "- Two."), "one paragraph")
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



# Git without the user's or the system's config, so signing or hooks set there
# can't affect the scratch repositories.
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


class GitRepo(Repo):
    """A Repo that is also a git repository on branch dev, with no remote."""

    def __init__(self):
        super().__init__()
        self.git("init", "-q", "-b", "dev")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "start")

    def git(self, *args):
        out = subprocess.run(["git", *args], cwd=self.root, env=GIT_ENV, check=True, capture_output=True, text=True)
        return out.stdout.strip()

    def commit_fragment(self, name, text, message):
        """Write a fragment and commit it on the current branch."""
        (self.dir / name).write_text(text, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def merge_fragment(self, name, text, branch, into="dev"):
        """Add a fragment on a new branch and merge it with a merge commit; return that commit."""
        self.git("checkout", "-q", "-b", branch)
        self.commit_fragment(name, text, f"add {name}")
        self.git("checkout", "-q", into)
        self.git("merge", "-q", "--no-ff", "-m", f"Merge {branch}", branch)
        return self.git("rev-parse", "HEAD")


def link(sha):
    return f"([{sha[:7]}](https://github.com/jscott3201/rusty-bacnet/commit/{sha}))"


class CommitLinkTests(unittest.TestCase):
    def test_entries_link_the_commit_that_brought_them_into_dev(self):
        with GitRepo() as repo:
            merge = repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5", "  wrapped (#5)."), "fix-5")
            # Committed straight to dev: that commit brought it in.
            direct = repo.commit_fragment("6-b.md", fragment("Fixed", "- Fix 6 (#6)."), "add 6-b")
            # Not committed anywhere yet: no link and no error.
            (repo.dir / "7-c.md").write_text(fragment("Fixed", "- Fix 7 (#7)."), encoding="utf-8")
            code, out, err = repo.run("assemble", "--version", "1.1.0", "--date", "2026-10-02")
            self.assertEqual((code, err), (0, ""), out)
            text = repo.changelog.read_text(encoding="utf-8")
            self.assertIn(
                "### Fixed\n\n"
                f"- Fix 5\n  wrapped (#5). {link(merge)}\n\n"
                f"- Fix 6 (#6). {link(direct)}\n\n"
                "- Fix 7 (#7).\n\n## [1.0.0]",
                text,
            )
            # The release workflow's notes extractor takes the linked entries as they are.
            self.assertIn(link(merge), changelog_notes.extract(text, "1.1.0"))

    def test_the_merge_commit_wins_over_the_branch_commit(self):
        with GitRepo() as repo:
            merge = repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5")
            self.assertNotEqual(merge, repo.git("rev-parse", "fix-5"))
            self.assertIn(f"- Fix 5. {link(merge)}\n", repo.run("preview")[1])

    def test_a_fragment_added_again_links_the_latest_addition(self):
        with GitRepo() as repo:
            repo.merge_fragment("5-a.md", fragment("Fixed", "- Old 5."), "old-5")
            (repo.dir / "5-a.md").unlink()
            repo.git("commit", "-q", "-am", "release")
            again = repo.merge_fragment("5-a.md", fragment("Fixed", "- New 5."), "new-5")
            self.assertIn(f"- New 5. {link(again)}\n", repo.run("preview")[1])

    def test_a_fragment_merged_through_another_branch_links_dev_merge(self):
        with GitRepo() as repo:
            repo.git("checkout", "-q", "-b", "side")
            repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5", into="side")
            repo.git("checkout", "-q", "dev")
            repo.git("merge", "-q", "--no-ff", "-m", "Merge side", "side")
            # dev's merge of side brought it into dev, not the merge into side.
            self.assertIn(f"- Fix 5. {link(repo.git('rev-parse', 'HEAD'))}\n", repo.run("preview")[1])

    def test_a_bulk_move_of_fragments_links_none_of_them(self):
        with GitRepo() as repo:
            merge = repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5")
            for i in range(cl.BULK_ADDS + 1):
                (repo.dir / f"{100 + i}-moved.md").write_text(fragment("Fixed", f"- Moved {i}."), encoding="utf-8")
            repo.git("add", "-A")
            repo.git("commit", "-q", "-m", "move every entry into fragments")
            out = repo.run("preview")[1]
            self.assertIn(f"- Fix 5. {link(merge)}\n", out)
            self.assertIn("- Moved 0.\n", out)
            self.assertEqual(out.count("commit/"), 1)
            # One fragment fewer is an ordinary commit, and every entry links.
            repo.git("rm", "-q", f"changelog.d/{100 + cl.BULK_ADDS}-moved.md")
            repo.git("commit", "-q", "-m", "drop one")
            repo.git("reset", "-q", "--soft", "HEAD~2")
            repo.git("commit", "-q", "-m", "move one fewer")
            self.assertEqual(repo.run("preview")[1].count("commit/"), cl.BULK_ADDS + 1)

    def test_shallow_clone_gets_no_links(self):
        # A shallow clone's oldest commit seems to add every file, so it proves nothing.
        with GitRepo() as repo:
            repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5")
            clone = Path(repo.root, "clone")
            repo.git("clone", "-q", "--depth", "1", f"file://{repo.root}", str(clone))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cl.main(["--root", str(clone), "preview"]), 0)
            self.assertIn("- Fix 5.\n", out.getvalue())
            self.assertNotIn("commit/", out.getvalue())

    def test_a_directory_inside_another_repository_gets_no_links(self):
        with GitRepo() as repo:
            repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5")
            inner = Path(repo.root, "inner")
            (inner / "changelog.d").mkdir(parents=True)
            (inner / "changelog.d" / "5-a.md").write_text(fragment("Fixed", "- Fix 5."), encoding="utf-8")
            self.assertEqual(cl.commit_links(inner, cl.load_fragments(inner / "changelog.d")), {})

    def test_outside_git_there_are_no_links(self):
        with Repo(fragments={"5-a.md": fragment("Fixed", "- A.")}) as repo:
            self.assertEqual(cl.commit_links(repo.root, cl.load_fragments(repo.dir)), {})


class CommitPinTests(unittest.TestCase):
    def pin_text(self, pin, entry="- Fix 5."):
        return f"---\nsection: Fixed\ncommit: {pin}\n---\n{entry}\n"

    def test_pin_is_parsed_and_must_be_lowercase_hex_of_7_to_40(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "5-a.md")
            for pin, ok in (("abcdef0", True), ("a" * 40, True), ("abcdef", False), ("a" * 41, False), ("ABCDEF0", False), ("xyzxyzx", False)):
                with self.subTest(pin=pin):
                    path.write_text(self.pin_text(pin), encoding="utf-8")
                    if ok:
                        self.assertEqual(cl.parse_fragment(path).commit, pin)
                    else:
                        with self.assertRaisesRegex(cl.ChangelogError, "5-a.md:3: commit .* is not 7 to 40"):
                            cl.parse_fragment(path)
            path.write_text("---\nsection: Fixed\nfoo: bar\n---\n- Fix 5.\n", encoding="utf-8")
            with self.assertRaisesRegex(cl.ChangelogError, "optionally 'commit: <sha>'"):
                cl.parse_fragment(path)

    def test_a_pin_wins_over_history(self):
        with GitRepo() as repo:
            merge = repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5")
            added = repo.commit_fragment("6-b.md", fragment("Fixed", "- Fix 6."), "adds 6")
            (repo.dir / "5-a.md").write_text(self.pin_text(added[:10]), encoding="utf-8")
            (repo.dir / "6-b.md").write_text(self.pin_text(merge, "- Fix 6."), encoding="utf-8")
            out = repo.run("preview")[1]
            self.assertIn(f"- Fix 5. {link(added)}\n", out)  # an abbreviated pin links the full SHA
            self.assertIn(f"- Fix 6. {link(merge)}\n", out)  # not the commit that added the fragment
            self.assertEqual(repo.run("check")[0], 0)

    def test_a_pin_names_an_entry_in_a_bulk_move(self):
        with GitRepo() as repo:
            for i in range(cl.BULK_ADDS + 1):
                (repo.dir / f"{100 + i}-moved.md").write_text(fragment("Changed", f"- Moved {i}."), encoding="utf-8")
            repo.git("add", "-A")
            repo.git("commit", "-q", "-m", "bulk")
            sha = repo.git("rev-parse", "HEAD")
            self.assertEqual(repo.run("preview")[1].count("commit/"), 0)
            (repo.dir / "100-moved.md").write_text(self.pin_text(sha, "- Moved 0.").replace("Fixed", "Changed"), encoding="utf-8")
            self.assertIn(f"- Moved 0. {link(sha)}\n", repo.run("preview")[1])

    def test_a_pin_naming_an_unknown_commit_fails_check(self):
        with GitRepo() as repo:
            start = repo.git("rev-parse", "HEAD")
            repo.git("checkout", "-q", "-b", "side")
            side = repo.commit_fragment("9-z.md", fragment("Fixed", "- Z."), "side commit")
            repo.git("checkout", "-q", "dev")
            repo.git("merge", "-q", "--no-ff", "-m", "Merge side", "side")
            for pin in ("1234567", side):  # unknown, and a commit off the first-parent line
                with self.subTest(pin=pin):
                    (repo.dir / "5-a.md").write_text(self.pin_text(pin), encoding="utf-8")
                    code, _, err = repo.run("check")
                    self.assertEqual(code, 1)
                    self.assertIn(f"5-a.md: commit {pin} is on no mainline's first-parent history", err)
            (repo.dir / "5-a.md").write_text(self.pin_text(start), encoding="utf-8")
            self.assertEqual(repo.run("check")[0], 0)

    def test_a_pin_to_a_dev_merge_passes_on_a_branch_that_merged_dev(self):
        with GitRepo() as repo:
            repo.git("checkout", "-q", "-b", "feature")
            repo.commit_fragment("7-f.md", fragment("Fixed", "- F."), "feature work")
            repo.git("checkout", "-q", "dev")
            merge = repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5")
            (repo.dir / "5-a.md").write_text(self.pin_text(merge), encoding="utf-8")
            repo.git("commit", "-q", "-am", "pin 5")
            repo.git("checkout", "-q", "feature")
            repo.git("merge", "-q", "--no-ff", "-m", "Merge dev", "dev")
            self.assertEqual(repo.run("check")[0], 0)  # the pin is off feature's first-parent line
            repo.git("branch", "-q", "-m", "dev", "upstream")
            code, _, err = repo.run("check")  # without a dev ref, only HEAD's line counts
            self.assertEqual(code, 1)
            self.assertIn("5-a.md: commit", err)

    def test_a_pin_to_a_dev_merge_passes_while_merging_it(self):
        with GitRepo() as repo:
            repo.git("checkout", "-q", "-b", "feature")
            repo.commit_fragment("7-f.md", fragment("Fixed", "- F."), "feature work")
            repo.git("checkout", "-q", "dev")
            merge = repo.merge_fragment("5-a.md", fragment("Fixed", "- Fix 5."), "fix-5")
            (repo.dir / "5-a.md").write_text(self.pin_text(merge), encoding="utf-8")
            repo.git("commit", "-q", "-am", "pin 5")
            repo.git("checkout", "-q", "feature")
            repo.git("branch", "-q", "-m", "dev", "upstream")
            repo.git("merge", "-q", "--no-ff", "--no-commit", "upstream")
            self.assertEqual(repo.run("check")[0], 0)  # MERGE_HEAD's line holds the pin
            repo.git("merge", "--abort")
            (repo.dir / "5-a.md").write_text(self.pin_text(merge), encoding="utf-8")
            self.assertEqual(repo.run("check")[0], 1)

    def test_a_shallow_clone_skips_the_pin_check(self):
        with GitRepo() as repo:
            repo.commit_fragment("5-a.md", self.pin_text("1234567"), "add 5")
            self.assertEqual(repo.run("check")[0], 1)
            clone = Path(repo.root, "clone")
            repo.git("clone", "-q", "--depth", "1", f"file://{repo.root}", str(clone))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cl.main(["--root", str(clone), "check"]), 0)
            self.assertIn("OK", out.getvalue())


class BackfillTests(unittest.TestCase):
    def backfill(self, repo, *args, root=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pin_commits.main(["--root", str(root or repo.root), *args])
        return code, out.getvalue(), err.getvalue()

    def merge_pr(self, repo, issue, name, pr):
        """Merge a branch adding a fragment, with a Forgejo-style subject naming issue; return the merge."""
        repo.git("checkout", "-q", "-b", f"b{pr}")
        repo.commit_fragment(name, fragment("Fixed", f"- Fix {issue}."), f"work {pr}")
        repo.git("checkout", "-q", "dev")
        subject = f"Merge pull request 'fix: thing (#{issue}, #99)' (#{pr}) from b{pr} into dev"
        repo.git("merge", "-q", "--no-ff", "-m", subject, f"b{pr}")
        return repo.git("rev-parse", "HEAD")

    def commit_all(self, repo, message):
        repo.git("add", "-A")
        repo.git("commit", "-q", "-m", message)

    def test_pins_the_one_merge_and_is_idempotent(self):
        with GitRepo() as repo:
            for i in range(cl.BULK_ADDS + 1):
                (repo.dir / f"{100 + i}-moved.md").write_text(fragment("Changed", f"- Moved {i}."), encoding="utf-8")
            for name in ("7-solo.md", "8-twice.md", "nonum.md"):
                (repo.dir / name).write_text(fragment("Fixed", f"- {name}."), encoding="utf-8")
            self.commit_all(repo, "bulk")
            first = self.merge_pr(repo, 100, "999-other.md", 11)
            self.merge_pr(repo, 8, "998-x.md", 12)
            self.merge_pr(repo, 8, "997-y.md", 13)
            seven = self.merge_pr(repo, 7, "996-z.md", 14)
            code, out, _ = self.backfill(repo)
            self.assertEqual(code, 0)
            self.assertIn("pinned 2 fragment(s); 1 ambiguous and 21 unmatched", out)
            self.assertIn("ambiguous: changelog.d/8-twice.md", out)
            self.assertEqual(
                (repo.dir / "7-solo.md").read_text(encoding="utf-8"),
                f"---\nsection: Fixed\ncommit: {seven}\n---\n- 7-solo.md.\n",
            )
            self.assertIn(f"commit: {first}\n", (repo.dir / "100-moved.md").read_text(encoding="utf-8"))
            for name in ("8-twice.md", "nonum.md"):
                self.assertNotIn("commit:", (repo.dir / name).read_text(encoding="utf-8"))
            self.assertEqual(repo.run("check")[0], 0)
            self.commit_all(repo, "pins")
            before = {p.name: p.read_text(encoding="utf-8") for p in repo.dir.iterdir()}
            code, out, _ = self.backfill(repo)
            self.assertEqual(code, 0)
            self.assertIn("pinned 0 fragment(s)", out)
            self.assertEqual(before, {p.name: p.read_text(encoding="utf-8") for p in repo.dir.iterdir()})

    def test_a_pull_request_number_is_not_an_issue(self):
        with GitRepo() as repo:
            for i in range(cl.BULK_ADDS):
                (repo.dir / f"{100 + i}-moved.md").write_text(fragment("Changed", f"- Moved {i}."), encoding="utf-8")
            (repo.dir / "11-pr-number.md").write_text(fragment("Fixed", "- Fix 11."), encoding="utf-8")
            self.commit_all(repo, "bulk, so no fragment links")
            self.merge_pr(repo, 5, "5-a.md", 11)
            self.assertIn("pinned 0 fragment(s)", self.backfill(repo)[1])

    def test_dry_run_writes_nothing_and_a_shallow_clone_is_refused(self):
        with GitRepo() as repo:
            for i in range(cl.BULK_ADDS):  # with 7-solo.md, one more than a commit may add and still link
                (repo.dir / f"{100 + i}-moved.md").write_text(fragment("Changed", f"- Moved {i}."), encoding="utf-8")
            (repo.dir / "7-solo.md").write_text(fragment("Fixed", "- Fix 7."), encoding="utf-8")
            self.commit_all(repo, "bulk")
            self.merge_pr(repo, 7, "996-z.md", 14)
            self.assertIn("would pin 1 fragment(s)", self.backfill(repo, "--dry-run")[1])
            self.assertNotIn("commit:", (repo.dir / "7-solo.md").read_text(encoding="utf-8"))
            clone = Path(repo.root, "clone")
            repo.git("clone", "-q", "--depth", "1", f"file://{repo.root}", str(clone))
            code, _, err = self.backfill(repo, root=clone)
            self.assertEqual(code, 1)
            self.assertIn("shallow", err)


if __name__ == "__main__":
    unittest.main()
