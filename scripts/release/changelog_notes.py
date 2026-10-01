#!/usr/bin/env python3
"""Print one CHANGELOG.md section as release notes (#943).

    changelog_notes.py --version 0.12.0 [--changelog CHANGELOG.md]
    changelog_notes.py --unreleased
    changelog_notes.py --version 0.12.0 --max-chars 125000 --full-url URL

A section runs from its `## [<name>]` heading to the next level-2 heading,
ignoring headings inside fenced code blocks. The heading itself is left out.
The script fails if the section is missing or empty.

GitHub refuses release bodies over 125,000 characters. With --max-chars, a
longer section is cut at the last blank line that fits and ends with a link to
the full changelog (--full-url).
"""

import argparse
import re
import sys
from pathlib import Path

HEADING = re.compile(r"^## \[([^\]]+)\]")
FENCE = re.compile(r"^\s*(```|~~~)")


class NotesError(Exception):
    """The changelog has no usable section for the requested version."""


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
        raise NotesError(f"CHANGELOG.md's '## [{name}]' section is empty")
    return body + "\n"


def truncate(body, max_chars, full_url):
    """Cut body to at most max_chars characters, ending with a link to full_url."""
    if len(body) <= max_chars:
        return body
    footer = f"\n_These notes are cut short. The full list is in [CHANGELOG.md]({full_url})._\n"
    room = max_chars - len(footer)
    if room <= 0:
        raise NotesError(f"--max-chars {max_chars} leaves no room for the notes")
    cut = body.rfind("\n\n", 0, room)
    if cut <= 0:
        cut = body.rfind("\n", 0, room)
    if cut <= 0:
        cut = room
    return body[:cut].rstrip("\n") + "\n" + footer


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--version", help="release version, for example 0.12.0")
    which.add_argument("--unreleased", action="store_true", help="the [Unreleased] section")
    parser.add_argument("--changelog", default="CHANGELOG.md", type=Path)
    parser.add_argument("--max-chars", type=int, help="cut longer notes to this many characters")
    parser.add_argument("--full-url", help="link to the full changelog, required with --max-chars")
    args = parser.parse_args(argv)
    if args.max_chars is not None and not args.full_url:
        parser.error("--max-chars needs --full-url")

    name = "Unreleased" if args.unreleased else args.version.removeprefix("v")
    try:
        body = extract(args.changelog.read_text(encoding="utf-8"), name)
        if args.max_chars is not None:
            body = truncate(body, args.max_chars, args.full_url)
    except (NotesError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
