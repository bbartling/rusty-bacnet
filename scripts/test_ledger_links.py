#!/usr/bin/env python3
"""Unit tests for check_ledger_links.py:
python3 -m unittest discover -s scripts -p 'test_ledger_links.py'"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import check_ledger_links as cll

LEDGER_PAGE = """# Ledger

## Hub outcome status

Defined by [`hub_outcome`](../../crates/a/src/hub.rs) in [the hub](../../crates/a/src/hub.rs).
See the [summary rows](support-summary.md#ledger-rows) and [above](#hub-outcome-status).

```text
[not a link](missing.md#nowhere)
```
"""
SUMMARY_PAGE = "# Summary\n\n## Ledger Rows\n"
DEV = "https://github.com/jscott3201/rusty-bacnet/blob/dev/docs/conformance/"


class Tree:
    """A throwaway checkout holding the two conformance pages and given extra files."""

    def __init__(self, files: dict[str, str]):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        base = {
            "docs/conformance/standard-135-2020-ledger.md": LEDGER_PAGE,
            "docs/conformance/support-summary.md": SUMMARY_PAGE,
            "crates/a/src/hub.rs": "pub fn hub_outcome() {}\n",
        }
        for rel, text in {**base, **files}.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def problems(self) -> list[tuple[str, int, str]]:
        found = cll.links_into(self.root) + cll.links_out(self.root)
        return [(p.file, p.line, p.rule) for p in found]

    def close(self):
        self._tmp.cleanup()


class LinkChecks(unittest.TestCase):
    def tree(self, files: dict[str, str] | None = None) -> Tree:
        tree = Tree(files or {})
        self.addCleanup(tree.close)
        return tree

    def test_good_links_pass(self):
        tree = self.tree(
            {
                "README.md": "[ledger](docs/conformance/standard-135-2020-ledger.md)\n",
                "docs/rust-api.md": "See [hub\nstatus](conformance/standard-135-2020-ledger.md#hub-outcome-status).\n",
                "docs/design/x.md": "[rows](../conformance/support-summary.md#ledger-rows)\n",
                "changelog.d/1-x.md": "- [evidence](docs/conformance/standard-135-2020-ledger.md#hub-outcome-status) (#1).\n",
                "website/src/content/docs/a.md": f"[s]({DEV}support-summary.md#ledger-rows)\n",
                "CHANGELOG.md": "[ref]: docs/conformance/support-summary.md#ledger-rows\n",
            }
        )
        self.assertEqual(tree.problems(), [])

    def test_broken_links_into_the_pages_fail(self):
        tree = self.tree(
            {
                "README.md": "x\n[gone](docs/conformance/standard-135-2020-ledger.md#no-such-heading)\n",
                "docs/rust-api.md": "[wrong dir](standard-135-2020-ledger.md#hub-outcome-status)\n",
                "changelog.d/1-x.md": "[rel to fragment](../docs/conformance/support-summary.md#ledger-rows-x)\n",
                "website/src/content/docs/a.mdx": f"[s]({DEV}standard-135-2020-ledger.md#renamed)\n",
                "CHANGELOG.md": "[ref]: docs/conformance/support-summary.md#old-name\n",
            }
        )
        self.assertEqual(
            sorted(tree.problems()),
            [
                ("CHANGELOG.md", 1, "link-into"),
                ("README.md", 2, "link-into"),
                ("changelog.d/1-x.md", 1, "link-into"),
                ("docs/rust-api.md", 1, "link-into"),
                ("website/src/content/docs/a.mdx", 1, "link-into"),
            ],
        )

    def test_tagged_and_external_links_are_skipped(self):
        tree = self.tree(
            {
                "website/src/content/docs/a.md": (
                    "[v0.11](https://github.com/jscott3201/rusty-bacnet/blob/v0.11.0/docs/conformance/standard-135-2020-ledger.md#gone)\n"
                    "[other](https://example.com/standard-135-2020-ledger.md#gone)\n"
                ),
            }
        )
        self.assertEqual(tree.problems(), [])

    def test_broken_links_out_of_a_conformance_page_fail(self):
        page = LEDGER_PAGE + (
            "\n[moved](../../crates/a/src/old.rs)\n"
            "[`renamed_fn`](../../crates/a/src/hub.rs)\n"
            "[rows](support-summary.md#no-rows)\n"
            "[self](#no-such-section)\n"
        )
        tree = self.tree({"docs/conformance/standard-135-2020-ledger.md": page})
        first = LEDGER_PAGE.count("\n") + 2  # the page ends in a newline, then one blank line
        self.assertEqual(
            tree.problems(),
            [("docs/conformance/standard-135-2020-ledger.md", first + n, "link-out") for n in range(4)],
        )

    def test_check_prints_rule_and_fix(self):
        tree = self.tree({"README.md": "[x](docs/conformance/support-summary.md#nope)\n"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cll.check(tree.root), 1)
        self.assertIn("README.md:1: [link-into]", out.getvalue())
        self.assertIn("fix: " + cll.HINTS["link-into"], out.getvalue())

    def test_current_checkout_has_no_broken_ledger_links(self):
        self.assertEqual([str(p) for p in cll.links_into() + cll.links_out()], [])


if __name__ == "__main__":
    unittest.main()
