#!/usr/bin/env python3
"""Print one CHANGELOG.md section as release notes (#943).

    changelog_notes.py --version 0.12.0 [--changelog CHANGELOG.md] [--allow-empty]
    changelog_notes.py --version 0.12.0 --github --max-chars 125000 --full-url URL

A section runs from its `## [<name>]` heading to the next level-2 heading,
ignoring headings inside fenced code blocks. The heading itself is left out.
The script fails if the section is missing or empty; with --allow-empty (dry
runs), an empty section gives a one-line placeholder instead. Unreleased
entries are fragments in changelog.d/, so a dry run reads a copy that
`scripts/changelog.py assemble --output` wrote.

GitHub refuses release bodies over 125,000 characters. With --max-chars, a
longer section is cut at the last blank line that fits and ends with a link to
the full changelog (--full-url). The result is never longer than --max-chars,
and a code block the cut leaves open is closed.

Issue numbers are Forgejo's, and GitHub would link a bare #1134 to its own
item of that number. With --github (the GitHub release copy, #1188), a
zero-width space after each issue reference's # stops that, and a first line
says where the numbers live; code, link targets and fenced blocks keep theirs.
"""

import argparse
import re
import sys
from pathlib import Path

HEADING = re.compile(r"^## \[([^\]]+)\]")
FENCE = re.compile(r"^\s*(```|~~~)")
FENCE_RUN = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
# Code spans and link targets, which GitHub doesn't autolink and a reader may copy.
PROTECTED = re.compile(r"(`+[^`]*`+|\]\([^)]*\))")
# An issue reference GitHub would autolink: # and digits, not inside a word,
# path, link text or character reference.
ISSUE_REF = re.compile(r"(?<![\w&/\[])#(\d+)\b")
GITHUB_NOTE = "_Issue numbers refer to the project's Forgejo tracker, not to this repository's issues._"


class NotesError(Exception):
    """The changelog has no usable section for the requested version."""


class EmptySection(NotesError):
    """The section exists but has nothing in it."""


def extract(text, name):
    """Return the body of the `## [name]` section, without its heading."""
    lines = text.splitlines()
    start = None
    in_fence = False
    end = len(lines)
    for i, line in enumerate(lines):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("## "):
            if start is not None:
                end = i
                break
            m = HEADING.match(line)
            if m and m.group(1).strip().lower() == name.lower():
                start = i + 1
    if start is None:
        raise NotesError(f"CHANGELOG.md has no '## [{name}]' section")
    body = "\n".join(lines[start:end]).strip("\n")
    if not body.strip():
        raise EmptySection(f"CHANGELOG.md's '## [{name}]' section is empty")
    return body + "\n"


def github_refs(body):
    """body with issue references GitHub won't autolink, led by GITHUB_NOTE if there were any."""
    out = []
    in_fence = False
    changed = False
    for line in body.split("\n"):
        if FENCE.match(line):
            in_fence = not in_fence
        if in_fence or FENCE.match(line):
            out.append(line)
            continue
        parts = PROTECTED.split(line)
        for i in range(0, len(parts), 2):  # odd indexes are the protected spans
            parts[i], count = ISSUE_REF.subn(r"#&#8203;\1", parts[i])
            changed = changed or count > 0
        out.append("".join(parts))
    text = "\n".join(out)
    return f"{GITHUB_NOTE}\n\n{text}" if changed else text


def open_fence(text):
    """The fence that opens a code block text leaves unclosed, or None."""
    opened = None
    for line in text.splitlines():
        m = FENCE_RUN.match(line)
        if not m:
            continue
        run = m.group(1)
        if opened is None:
            opened = run
        elif run[0] == opened[0] and len(run) >= len(opened) and not m.group(2).strip():
            opened = None
    return opened


def cut_at(body, limit):
    """body cut before limit, at a blank line if there is one, else at a line end."""
    for sep in ("\n\n", "\n"):
        cut = body.rfind(sep, 0, limit)
        if cut > 0:
            return body[:cut]
    return body[:limit]


def truncate(body, max_chars, full_url):
    """Cut body to at most max_chars characters, ending with a link to full_url."""
    if len(body) <= max_chars:
        return body
    footer = f"\n_These notes are cut short. The full list is in [CHANGELOG.md]({full_url})._\n"
    limit = max_chars - len(footer)
    while limit > 0:
        kept = cut_at(body, limit).rstrip("\n") + "\n"
        fence = open_fence(kept)
        if fence:
            kept += fence + "\n"
        if len(kept) + len(footer) <= max_chars:
            return kept + footer
        limit -= len(kept) + len(footer) - max_chars
    raise NotesError(f"--max-chars {max_chars} leaves no room for the notes")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version, for example 0.12.0")
    parser.add_argument("--changelog", default="CHANGELOG.md", type=Path)
    parser.add_argument("--max-chars", type=int, help="cut longer notes to this many characters")
    parser.add_argument("--full-url", help="link to the full changelog, required with --max-chars")
    parser.add_argument("--allow-empty", action="store_true", help="an empty section gives a placeholder")
    parser.add_argument("--github", action="store_true", help="keep GitHub from linking issue numbers to its own")
    args = parser.parse_args(argv)
    if args.max_chars is not None and not args.full_url:
        parser.error("--max-chars needs --full-url")

    name = args.version.removeprefix("v")
    try:
        try:
            body = extract(args.changelog.read_text(encoding="utf-8"), name)
        except EmptySection:
            if not args.allow_empty:
                raise
            body = f"No changes are listed under {name} yet.\n"
        if args.github:
            body = github_refs(body)
        if args.max_chars is not None:
            body = truncate(body, args.max_chars, args.full_url)
    except (NotesError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
