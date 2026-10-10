"""ELF triage: header, sections, dynamic entries, symbols, and the heuristics."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from revlab import elf, heuristics

from . import fixtures


class ElfParseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, **kwargs) -> Path:
        path = self.root / name
        path.write_bytes(fixtures.build_elf(**kwargs))
        return path

    def test_header_and_dynamic_entries(self) -> None:
        info = elf.parse(self._write("libfoo.so"))
        self.assertTrue(info.valid, info.error)
        self.assertEqual(info.bits, 64)
        self.assertEqual(info.endian, "little")
        self.assertEqual(info.type_name, "DYN")
        self.assertEqual(info.machine, "x86_64")
        self.assertEqual(info.abi, "x86_64-64")
        self.assertEqual(info.soname, "libfoo.so")
        self.assertEqual(info.needed, ["libc.so", "liblog.so"])
        self.assertEqual(info.entry, 0x1000)

    def test_comment_banner_and_sections(self) -> None:
        info = elf.parse(self._write("libfoo.so"))
        self.assertIn("clang version 14.0.7", info.banner)
        self.assertIn(".dynstr", info.section_names)
        self.assertIn(".comment", info.section_names)
        self.assertTrue(info.stripped)  # this fixture has no .symtab

    def test_symbols_are_read_when_present(self) -> None:
        path = self._write(
            "libjni.so",
            exports=("Java_com_example_demo_nativeCall", "JNI_OnLoad"),
        )
        info = elf.parse(path)
        self.assertIn("Java_com_example_demo_nativeCall", info.exports)
        self.assertIn("JNI_OnLoad", info.exports)
        self.assertEqual(
            sorted(info.jni_entry_points),
            ["JNI_OnLoad", "Java_com_example_demo_nativeCall"],
        )

    def test_unstripped_when_symtab_present(self) -> None:
        info = elf.parse(self._write("libdebug.so", with_symtab=True))
        self.assertFalse(info.stripped)
        self.assertIn(".symtab", info.section_names)

    def test_not_an_elf_is_reported_not_raised(self) -> None:
        path = self.root / "notes.txt"
        path.write_bytes(b"dex\n035\x00 not an elf")
        info = elf.parse(path)
        self.assertFalse(info.valid)
        self.assertIn("bad magic", info.error or "")
        self.assertFalse(elf.is_elf(path))

    def test_missing_file_is_reported(self) -> None:
        info = elf.parse(self.root / "absent.so")
        self.assertFalse(info.valid)
        self.assertIn("cannot read", info.error or "")

    def test_triage_dir_skips_non_elf_files(self) -> None:
        libs = self.root / "lib"
        fixtures.build_elf(libs / "x86_64" / "liba.so",
                           exports=("Java_com_example_a_native",))
        fixtures.build_elf(libs / "x86_64" / "libb.so", soname="libb.so")
        (libs / "x86_64" / "readme.txt").write_text("not elf", encoding="utf-8")

        infos = elf.triage_dir(libs)
        self.assertEqual(len(infos), 2)
        summary = elf.summarize(infos)
        self.assertEqual(summary["count"], 2)
        self.assertEqual(summary["by_abi"]["x86_64-64"], 2)
        self.assertEqual(summary["by_type"]["DYN"], 2)
        self.assertIn("libb.so", summary["shared_objects_without_exports"])
        self.assertNotIn("liba.so", summary["shared_objects_without_exports"])
        self.assertEqual(summary["not_stripped"], [])
        banner, count = next(iter(summary["by_banner"].items()))
        self.assertIn("clang version", banner)
        self.assertEqual(count, 2)


class ElfHeuristicsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _findings(self, name: str, **kwargs) -> list:
        path = self.root / name
        path.write_bytes(fixtures.build_elf(**kwargs))
        infos = [elf.parse(path)]
        return heuristics.elf_findings(infos, elf.summarize(infos))

    def test_register_natives_only_surface(self) -> None:
        findings = self._findings("libjni.so", exports=("JNI_OnLoad",))
        self.assertIn("register-natives-only", {finding.id for finding in findings})

    def test_zero_export_library_is_flagged(self) -> None:
        findings = self._findings("libopaque.so", exports=())
        ids = {finding.id for finding in findings}
        self.assertIn("no-exported-symbols", ids)
        self.assertIn("all-stripped", ids)

    def test_stale_toolchain_from_comment(self) -> None:
        findings = self._findings(
            "libold.so", banner="GCC: (GNU) 4.9.x 20150123", exports=("JNI_OnLoad",)
        )
        stale = [finding for finding in findings if finding.id == "stale-toolchain"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].severity, "low")

    def test_anti_analysis_symbols_detected(self) -> None:
        findings = self._findings("libguard.so", exports=("anti_debug_check",))
        anti = [finding for finding in findings if finding.id == "anti-analysis-symbols"]
        self.assertEqual(len(anti), 1)
        self.assertEqual(anti[0].severity, "high")

    def test_vendored_tls_detected(self) -> None:
        findings = self._findings(
            "libnet.so", needed=("libc.so", "libssl.so", "libcrypto.so")
        )
        self.assertIn("vendored-tls", {finding.id for finding in findings})

    def test_packer_library_name_is_only_a_hint(self) -> None:
        findings = self._findings("libjiagu.so", soname="libjiagu.so")
        packer = [finding for finding in findings if finding.id == "packer-lib-name"]
        self.assertEqual(len(packer), 1)
        self.assertEqual(packer[0].confidence, 0.5)  # naming alone proves nothing


class FormatIdentificationTests(unittest.TestCase):
    """Handing the ELF pass the wrong file must be named, not silently dropped."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, head: bytes) -> Path:
        path = self.root / name
        path.write_bytes(head)
        return path

    def test_sniff_names_the_common_formats(self) -> None:
        library = self.root / "libx.so"
        library.write_bytes(fixtures.build_elf())
        self.assertEqual(elf.sniff(library), "elf")
        self.assertEqual(elf.sniff(b"\x7fELF\x02\x01\x01\x00"), "elf")  # in-memory works too
        self.assertEqual(elf.sniff(self._write("app.exe", b"MZ\x90\x00" + b"\x00" * 32)), "pe")
        self.assertEqual(elf.sniff(self._write("classes.dex", b"dex\n035\x00")), "dex")
        self.assertEqual(elf.sniff(self._write("thing.apk", b"PK\x03\x04\x14\x00")), "zip")
        self.assertEqual(elf.sniff(self._write("nothing.bin", b"")), "empty")
        self.assertEqual(elf.sniff(self._write("blob.bin", b"\x01\x02\x03\x04")), "unknown")
        self.assertEqual(elf.sniff(self.root / "absent.bin"), "unreadable")

    def test_a_windows_exe_gets_a_reason_naming_the_ghidra_command(self) -> None:
        exe = self._write("app.exe", b"MZ" + b"\x00" * 64)
        result = elf.triage(exe)
        self.assertEqual(result.objects, [])
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(result.skipped[0].kind, "pe")
        self.assertIn("not an ELF", result.skipped[0].reason)
        self.assertIn("revlab ghidra summary", result.skipped[0].reason)
        self.assertIn("ghidra summary", result.unsupported_reason)

    def test_a_directory_of_exes_explains_itself_instead_of_saying_zero_objects(self) -> None:
        folder = self.root / "pe_only"
        folder.mkdir()
        (folder / "one.exe").write_bytes(b"MZ" + b"\x00" * 64)
        (folder / "two.dll").write_bytes(b"MZ" + b"\x00" * 64)
        result = elf.triage(folder)
        self.assertEqual(result.objects, [])
        self.assertEqual(result.skipped[0].kind, "no-match")
        self.assertIn("no ELF under", result.skipped[0].reason)
        self.assertIn("pe x2", result.skipped[0].reason)
        self.assertIn("ghidra summary", result.unsupported_reason)

    def test_a_pattern_match_that_is_not_elf_is_named_by_name(self) -> None:
        # A .so that is really a Windows DLL: pattern matches, magic does not.
        impostor = self._write("libfake.so", b"MZ" + b"\x00" * 64)
        result = elf.triage(self.root)
        self.assertEqual(result.objects, [])
        self.assertEqual([item.kind for item in result.skipped], ["pe"])
        self.assertEqual(result.skipped[0].path, str(impostor))

    def test_directory_triage_keeps_going_after_a_foreign_file(self) -> None:
        (self.root / "libgood.so").write_bytes(fixtures.build_elf())
        self._write("bad.bin", b"MZ" + b"\x00" * 64)
        result = elf.triage(self.root)
        self.assertEqual([Path(info.path).name for info in result.objects], ["libgood.so"])
        self.assertEqual([item.kind for item in result.skipped], ["pe"])
        self.assertEqual(result.unsupported_reason, "")  # objects were found: not an all-fail run

    def test_triage_dir_still_returns_objects_only(self) -> None:
        (self.root / "libgood.so").write_bytes(fixtures.build_elf())
        self._write("bad.bin", b"MZ" + b"\x00" * 64)
        self.assertEqual(len(elf.triage_dir(self.root)), 1)

    def test_a_truncated_elf_is_recorded_as_skipped_not_as_a_crash(self) -> None:
        broken = self._write("libbroken.so", b"\x7fELF" + b"\x00" * 60)
        result = elf.triage(broken)
        self.assertEqual(result.objects, [])
        self.assertEqual(result.skipped[0].kind, "elf")
        self.assertIn("could not be parsed", result.skipped[0].reason)


if __name__ == "__main__":
    unittest.main()
