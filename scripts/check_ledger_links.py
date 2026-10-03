#!/usr/bin/env python3
"""Check the links into and out of the conformance pages (#1209).

Into: a link to standard-135-2020-ledger.md or support-summary.md from
README.md, CHANGELOG.md, docs/, changelog.d/ or the website sources must name
an existing page, and its `#slug` must match a heading there (GitHub slug
rules, as check_ledger_anchors.py reads them). Relative links resolve from the
linking file's folder, except in changelog.d/ fragments, which resolve from the
repository root because the release assembles them into CHANGELOG.md. Website
pages link through GitHub URLs: a link into the `dev` branch resolves against
this checkout, and a link pinned to a tag or another branch is skipped.

Out: on a docs/conformance/ page, every relative link must name an existing
file, a `#slug` into a Markdown file must match a heading, and a link whose text
is one backticked name pointing at a .rs or .py file must name something that
file defines.

generate-conformance-docs.py --check runs this check, and CI's Lint job runs
it directly: python3 scripts/check_ledger_links.py
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

from check_ledger_anchors import heading_slugs

ROOT = Path(__file__).resolve().parents[1]
PAGES = ("standard-135-2020-ledger.md", "support-summary.md")
GITHUB_DEV = "https://github.com/jscott3201/rusty-bacnet/blob/dev/"
WEBSITE_SUFFIXES = (".md", ".mdx", ".astro", ".ts", ".mjs", ".js")
FENCE = re.compile(r"^\s*(```|~~~)")
# `[text](target "title")`, the text possibly wrapped over lines.
INLINE = re.compile(r"\[((?:[^\[\]\n]|\n(?!\s*\n))*)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
# `[label]: target` reference definitions.
REFERENCE = re.compile(r"^ {0,3}\[[^\]\n]+\]:\s*<?([^\s>]+)>?", re.M)
DEFINES = r"\b(?:fn|def|class|struct|enum|trait|type|const|static|mod|macro_rules!)\s+{}\b"

HINTS = {
    "link-into": "point the link at an existing heading of the page (GitHub slug: lower case, punctuation dropped, spaces as hyphens), or update it after a heading rename",
    "link-out": "fix the path (relative to docs/conformance/), the heading slug or the linked name",
}


@dataclass(frozen=True)
class Problem:
    """One broken link."""

    file: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: [{self.rule}] {self.detail}\n    fix: {HINTS[self.rule]}"


def _unfenced(text: str) -> str:
    """`text` with fenced code blocks blanked out, keeping line numbers."""
    out: list[str] = []
    fenced = False
    for line in text.split("\n"):
        if FENCE.match(line):
            fenced = not fenced
            out.append("")
        else:
            out.append("" if fenced else line)
    return "\n".join(out)


def links(text: str) -> list[tuple[int, str, str]]:
    """(line, text, target) of each inline link and reference definition outside fenced code."""
    text = _unfenced(text)
    found = [(m.start(), m.group(1), m.group(2)) for m in INLINE.finditer(text)]
    found += [(m.start(), "", m.group(1)) for m in REFERENCE.finditer(text)]
    return sorted((text.count("\n", 0, at) + 1, label, target) for at, label, target in found)


def sources(root: Path = ROOT) -> list[Path]:
    """The files whose links into the conformance pages are checked. The
    conformance pages themselves are left to links_out(), which checks every
    relative link on them."""
    conformance = root / "docs" / "conformance"
    files = [root / "README.md", root / "CHANGELOG.md", root / "website" / "README.md"]
    files += sorted(p for p in (root / "docs").rglob("*.md") if p.parent != conformance)
    files += sorted((root / "changelog.d").glob("*.md"))
    files += sorted(p for p in (root / "website" / "src").rglob("*") if p.suffix in WEBSITE_SUFFIXES)
    return [f for f in files if f.is_file()]


def _target_file(source: Path, target: str, root: Path) -> tuple[Path, str] | None:
    """The local file and slug a link names, or None for a link that leaves the checkout."""
    if target.startswith(GITHUB_DEV):
        target = target[len(GITHUB_DEV) :]
        base = root
    elif re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
        return None  # another URL scheme, or GitHub at a tag or another branch
    elif source.parent.name == "changelog.d" and source.parent.parent == root:
        base = root
    else:
        base = source.parent
    path_s, _, slug = target.partition("#")
    path_s = path_s.split("?", 1)[0]
    if path_s.startswith("/"):
        return root / path_s.lstrip("/"), slug
    return ((base / path_s) if path_s else source), slug


def _slugs(path: Path) -> set[str]:
    return heading_slugs(path.read_text(encoding="utf-8"))


def links_into(root: Path = ROOT) -> list[Problem]:
    """Broken links to the ledger page or the support summary."""
    out: list[Problem] = []
    for source in sources(root):
        rel = source.relative_to(root).as_posix()
        for line, _, target in links(source.read_text(encoding="utf-8")):
            resolved = _target_file(source, target, root)
            if resolved is None or resolved[0].name not in PAGES:
                continue
            path, slug = resolved
            if not path.is_file():
                out.append(Problem(rel, line, "link-into", f"`{target}` names no file"))
            elif slug and slug not in _slugs(path):
                out.append(Problem(rel, line, "link-into", f"`{target}` names no heading of {path.name}"))
    return out


def links_out(root: Path = ROOT) -> list[Problem]:
    """Broken relative links on the docs/conformance/ pages."""
    out: list[Problem] = []
    for page in sorted((root / "docs" / "conformance").glob("*.md")):
        rel = page.relative_to(root).as_posix()
        for line, label, target in links(page.read_text(encoding="utf-8")):
            resolved = _target_file(page, target, root)
            if resolved is None or target.startswith(GITHUB_DEV):
                continue
            path, slug = resolved
            if not path.exists():
                out.append(Problem(rel, line, "link-out", f"`{target}` names no file"))
                continue
            if slug and path.suffix == ".md" and slug not in _slugs(path):
                out.append(Problem(rel, line, "link-out", f"`{target}` names no heading of {path.name}"))
            name = re.fullmatch(r"\s*`(\w+)`\s*", label)
            if name and path.is_file() and path.suffix in (".rs", ".py"):
                if not re.search(DEFINES.format(re.escape(name.group(1))), path.read_text(encoding="utf-8")):
                    out.append(Problem(rel, line, "link-out", f"`{name.group(1)}` is not defined in {target}"))
    return out


def check(root: Path = ROOT) -> int:
    """Print every broken link; return 1 if there are any."""
    found = links_into(root) + links_out(root)
    for problem in found:
        print(problem)
    if found:
        print(f"{len(found)} broken conformance link(s)")
    return 1 if found else 0


def main() -> int:
    return check()


if __name__ == "__main__":
    sys.exit(main())
