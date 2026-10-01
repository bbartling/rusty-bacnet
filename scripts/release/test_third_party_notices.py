#!/usr/bin/env python3
"""Unit tests for third_party_notices.py (no cargo): python3 -m unittest discover -s scripts/release"""

import tempfile
import unittest
from pathlib import Path

import third_party_notices as tpn


class ParseTests(unittest.TestCase):
    def test_parse_tree(self):
        text = (
            "bacnet-cli v0.11.0 (/src/crates/bacnet-cli)\n"
            "tokio v1.53.1\n"
            "tokio v1.53.1 (*)\n"
            "bitflags v1.3.2\nbitflags v2.13.1\n\n"
        )
        self.assertEqual(tpn.parse_tree(text), {
            ("bacnet-cli", "0.11.0"), ("tokio", "1.53.1"), ("bitflags", "1.3.2"), ("bitflags", "2.13.1")})

    def test_normalize(self):
        self.assertEqual(tpn.normalize("\r\n\r\nMIT  \r\ntext\t\r\n\r\n"), "MIT\ntext\n")

    def test_two_sources_for_one_version_are_refused(self):
        packages = [{"name": "a", "version": "1.0.0"}, {"name": "a", "version": "1.0.0"}]
        with self.assertRaisesRegex(tpn.NoticesError, "two sources"):
            tpn.index_packages({"packages": packages})


class LicenseFilesTests(unittest.TestCase):
    def package(self, root, name="demo", **extra):
        return {"name": name, "version": "1.0.0", "manifest_path": str(root / "Cargo.toml"), **extra}

    def test_root_licence_files_and_declared_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("LICENSE-MIT", "LICENSE-APACHE", "COPYING", "NOTICE.txt", "README.md", "license.rs"):
                (root / name).write_text(f"{name}\n")
            (root / "legal").mkdir()
            (root / "legal" / "TERMS").write_text("terms\n")
            files = tpn.license_files(self.package(root, license_file="legal/TERMS"))
        self.assertEqual([f for f, _ in files], ["COPYING", "LICENSE-APACHE", "LICENSE-MIT", "NOTICE.txt", "legal/TERMS"])

    def test_extra_file_must_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "aws-lc").mkdir()
            (root / "aws-lc" / "LICENSE").write_text("OpenSSL and SSLeay\n")
            files = tpn.license_files(self.package(root, name="aws-lc-sys"))
            self.assertEqual(files, [("aws-lc/LICENSE", "OpenSSL and SSLeay\n")])
            (root / "aws-lc" / "LICENSE").unlink()
            with self.assertRaisesRegex(tpn.NoticesError, "no longer has aws-lc/LICENSE"):
                tpn.license_files(self.package(root, name="aws-lc-sys"))


class RenderTests(unittest.TestCase):
    def test_render_groups_identical_texts_and_lists_gaps(self):
        crates = [
            ("b", "2.0.0", "MIT", None, {"CLI"}, [("LICENSE", "MIT text\n")]),
            ("a", "1.0.0", "MIT OR Apache-2.0", None, {"CLI", "Python"},
             [("LICENSE-APACHE", "Apache text\n"), ("LICENSE-MIT", "MIT text\n")]),
            ("c", "0.1.0", "Zlib", "https://example.invalid/c", {"Python"}, []),
        ]
        text = tpn.render("1.2.3", "Our MIT\n", crates, ("1.10.7", "libpcap licence\n"))
        self.assertIn("Rusty BACnet 1.2.3 release binaries", text)
        self.assertIn("a 1.0.0: MIT OR Apache-2.0 [CLI Python]", text)
        self.assertIn("libpcap 1.10.7: BSD-3-Clause [CLI]", text)
        self.assertIn("libpcap licence", text)
        self.assertEqual(text.count("MIT text"), 1)
        self.assertIn("  a 1.0.0 (LICENSE-MIT)\n  b 2.0.0 (LICENSE)\n", text)
        self.assertIn("c 0.1.0: Zlib, https://example.invalid/c", text)
        self.assertLess(text.index("Apache text"), text.index("MIT text"))
        self.assertEqual(text, tpn.render("1.2.3", "Our MIT\n", list(reversed(crates)), ("1.10.7", "libpcap licence\n")))


if __name__ == "__main__":
    unittest.main()
