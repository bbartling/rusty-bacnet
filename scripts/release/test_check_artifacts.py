#!/usr/bin/env python3
"""Unit tests for check_artifacts.py (no ELF files): python3 -m unittest discover -s scripts/release"""

import unittest

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
        errors, version, wheels = checks.check_wheel_set(self.names(), self.PY, self.ARCH)
        self.assertEqual((errors, version, len(wheels)), ([], "1.2.0", 4))

    def test_missing_and_unexpected_wheels(self):
        names = self.names()[:-1] + ["rusty_bacnet-1.2.0-cp312-cp312-manylinux_2_39_x86_64.whl"]
        errors, _, _ = checks.check_wheel_set(names, self.PY, self.ARCH)
        self.assertTrue(any("missing wheel for tag cp312-cp312-manylinux_2_17_aarch64" in e for e in errors))
        self.assertTrue(any("unexpected wheel" in e and "2_39" in e for e in errors))

    def test_version_mismatch_and_missing_sdist(self):
        names = self.names()[1:] + ["rusty_bacnet-1.3.0.tar.gz"]
        names[0] = names[0].replace("1.2.0", "1.1.0")
        errors, _, _ = checks.check_wheel_set(names, self.PY, self.ARCH)
        self.assertTrue(any("has version 1.1.0, the sdist 1.3.0" in e for e in errors))
        errors, _, _ = checks.check_wheel_set(self.names()[1:], self.PY, self.ARCH)
        self.assertIn("expected one rusty_bacnet sdist, found 0", errors)

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
