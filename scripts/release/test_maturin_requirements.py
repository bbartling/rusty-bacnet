#!/usr/bin/env python3
"""maturin-requirements.txt agrees with .github/ci-pins.env (#1472):
python3 -m unittest discover -s scripts/release"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIREMENTS = ROOT / "scripts/release/maturin-requirements.txt"
PINS = ROOT / ".github/ci-pins.env"


def requirement_lines(text):
    """The requirement lines, continuations joined, comments and blanks left out."""
    joined = re.sub(r"\\\n", " ", text)
    return [" ".join(line.split()) for line in joined.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


class MaturinRequirementsTests(unittest.TestCase):
    def test_one_hash_pinned_maturin_at_the_pinned_version(self):
        pins = dict(re.findall(r"^([A-Z0-9_]+)=(\S+)$", PINS.read_text(encoding="utf-8"), re.MULTILINE))
        lines = requirement_lines(REQUIREMENTS.read_text(encoding="utf-8"))
        self.assertEqual(len(lines), 1, lines)
        match = re.fullmatch(r"maturin==(\S+)((?: --hash=sha256:[0-9a-f]{64})+)", lines[0])
        self.assertIsNotNone(match, f"not maturin==<version> with --hash=sha256:<hex> options: {lines[0]}")
        self.assertEqual(match[1], pins["MATURIN_VERSION"],
                         "maturin-requirements.txt and .github/ci-pins.env's MATURIN_VERSION must name one version;"
                         " update the file's hashes from https://pypi.org/pypi/maturin/<version>/json")
        hashes = re.findall(r"[0-9a-f]{64}", match[2])
        # One for each of the five build hosts' wheels (macOS Intel and Apple
        # Silicon may share the universal2 one), and none twice.
        self.assertEqual(len(hashes), len(set(hashes)))
        self.assertGreaterEqual(len(hashes), 4)

    def test_the_build_scripts_install_from_it_with_hashes(self):
        for script in ("build_linux.sh", "build_native.sh"):
            text = (ROOT / "scripts/release" / script).read_text(encoding="utf-8")
            with self.subTest(script=script):
                self.assertIn("--require-hashes --only-binary :all:", text)
                self.assertIn("-r scripts/release/maturin-requirements.txt", text)
                self.assertNotIn("MATURIN_VERSION", text)


if __name__ == "__main__":
    unittest.main()
