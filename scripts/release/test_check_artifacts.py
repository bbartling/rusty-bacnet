#!/usr/bin/env python3
"""Unit tests for check_artifacts.py (no ELF files): python3 -m unittest discover -s scripts/release"""

import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import check_artifacts as checks


class WheelSetTests(unittest.TestCase):
    PY = ["3.11", "3.12"]
    ARCH = ["x86_64", "aarch64"]

    def names(self, version="1.2.0"):
        out = [f"rusty_bacnet-{version}.tar.gz"]
        for py in ("cp311", "cp312"):
            for arch in self.ARCH:
                out.append(f"rusty_bacnet-{version}-{py}-{py}-manylinux_2_17_{arch}.manylinux2014_{arch}.whl")
        return out

    def test_complete_set(self):
        errors, wheels = checks.check_wheel_set(self.names(), self.PY, self.ARCH, "1.2.0")
        self.assertEqual((errors, len(wheels)), ([], 4))

    def test_missing_and_unexpected_wheels(self):
        names = self.names()[:-1] + ["rusty_bacnet-1.2.0-cp312-cp312-manylinux_2_39_x86_64.whl"]
        errors, _ = checks.check_wheel_set(names, self.PY, self.ARCH, "1.2.0")
        self.assertTrue(any("missing wheel for tag cp312-cp312-manylinux_2_17_aarch64" in e for e in errors))
        self.assertTrue(any("unexpected wheel" in e and "2_39" in e for e in errors))

    def test_version_mismatch_and_missing_sdist(self):
        names = self.names()[1:] + ["rusty_bacnet-1.3.0.tar.gz"]
        names[0] = names[0].replace("1.2.0", "1.1.0")
        errors, _ = checks.check_wheel_set(names, self.PY, self.ARCH, "1.2.0")
        self.assertTrue(any("has version 1.1.0, the release 1.2.0" in e for e in errors))
        self.assertTrue(any("rusty_bacnet-1.3.0.tar.gz has version 1.3.0, the release 1.2.0" in e for e in errors))
        errors, _ = checks.check_wheel_set(self.names()[1:], self.PY, self.ARCH, "1.2.0")
        self.assertIn("expected one rusty_bacnet sdist, found 0", errors)

    def test_pre_release_wheels_use_the_pep440_version(self):
        errors, _ = checks.check_wheel_set(self.names("1.2.0rc1"), self.PY, self.ARCH, checks.pep440("1.2.0-rc.1"))
        self.assertEqual(errors, [])

    def test_pep440(self):
        cases = {"0.12.0": "0.12.0", "1.0.0-rc.1": "1.0.0rc1", "1.0.0-alpha.2": "1.0.0a2", "1.0.0-beta": "1.0.0b0",
                 "2.0.0-dev.3": "2.0.0.dev3"}
        for cargo, python in cases.items():
            with self.subTest(cargo=cargo):
                self.assertEqual(checks.pep440(cargo), python)
        for bad in ("1.0", "1.0.0-nightly.1", "1.0.0-rc.x", "1.0.0+build"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checks.pep440(bad)

    def test_notices_in_wheels_and_sdist(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            notices = d / "THIRD-PARTY-NOTICES"
            notices.write_bytes(b"notices")
            good, bad, missing = (f"rusty_bacnet-1.2.0-cp31{i}-cp31{i}-x.whl" for i in (1, 2, 3))
            for name, payload in ((good, b"notices"), (bad, b"other")):
                with zipfile.ZipFile(d / name, "w") as whl:
                    whl.writestr("rusty_bacnet-1.2.0.dist-info/licenses/THIRD-PARTY-NOTICES", payload)
            with zipfile.ZipFile(d / missing, "w") as whl:
                whl.writestr("rusty_bacnet/__init__.py", "")
            with tarfile.open(d / "rusty_bacnet-1.2.0.tar.gz", "w:gz") as tar:
                tar.add(notices, "rusty_bacnet-1.2.0/crates/rusty-bacnet/THIRD-PARTY-NOTICES")
            errors = checks.check_notices(d, {1: good, 2: bad, 3: missing}, "1.2.0", notices)
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(any(bad in e and "differs" in e for e in errors))
        self.assertTrue(any(missing in e and "lacks" in e for e in errors))

    def test_extension_suffix(self):
        self.assertEqual(checks.extension_suffix("cp314", "aarch64"), ".cpython-314-aarch64-linux-gnu.so")


class ElfParsingTests(unittest.TestCase):
    def test_max_glibc(self):
        text = (
            "0000 DF *UND* 0000 (GLIBC_2.2.5) memcpy\n"
            "0000 DF *UND* 0000 (GLIBC_2.17) clock_gettime\n"
            "0000 DF *UND* 0000 (GLIBC_2.3) x\n0000 DF *UND* 0000 (GLIBC_PRIVATE) y\n"
        )
        self.assertEqual(checks.max_glibc(text), (2, 17))
        self.assertIsNone(checks.max_glibc("no versions"))
        self.assertGreater(checks.max_glibc("(GLIBC_2.34) z"), (2, 17))

    def test_readelf_parsing(self):
        header = "ELF Header:\n  Class:                             ELF64\n  Machine:                           AArch64\n"
        self.assertEqual(checks.elf_machine(header), "AArch64")
        self.assertIsNone(checks.elf_machine("nothing"))
        dynamic = (
            " 0x0000000000000001 (NEEDED)             Shared library: [libm.so.6]\n"
            " 0x0000000000000001 (NEEDED)             Shared library: [libpcap.so.0.8]\n"
            " 0x000000000000000c (INIT)               0x1000\n"
        )
        self.assertEqual(checks.needed_libraries(dynamic), ["libm.so.6", "libpcap.so.0.8"])


if __name__ == "__main__":
    unittest.main()
