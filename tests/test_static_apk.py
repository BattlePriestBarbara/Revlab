"""APK triage: AXML manifest parsing, ZIP/DEX inventory, entropy, extraction safety."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from revlab import heuristics, static_apk

from . import fixtures


class AxmlTests(unittest.TestCase):
    def test_manifest_fields_are_parsed(self) -> None:
        elements, strings = static_apk.parse_axml(fixtures.build_manifest_axml())
        names = [element["name"] for element in elements]
        self.assertEqual(names[0], "manifest")
        self.assertIn("application", names)
        self.assertIn("com.example.demo", strings)

        with tempfile.TemporaryDirectory() as tmp:
            apk = fixtures.build_manifest_apk(Path(tmp) / "demo.apk")
            manifest = static_apk.read_manifest(apk)

        self.assertIsNone(manifest.parse_error)
        self.assertEqual(manifest.package, "com.example.demo")
        self.assertEqual(manifest.version_name, "1.4.2")
        self.assertEqual(manifest.version_code, 7)
        self.assertEqual(manifest.min_sdk, 24)
        self.assertEqual(manifest.target_sdk, 34)
        self.assertEqual(manifest.application_class, "DemoApplication")
        self.assertTrue(manifest.debuggable)
        self.assertFalse(manifest.extract_native_libs)  # declared false in the fixture
        self.assertTrue(manifest.uses_clear_text_traffic)
        self.assertEqual(manifest.permissions, ["android.permission.SYSTEM_ALERT_WINDOW"])
        self.assertEqual(
            manifest.components["activity"], ["com.example.demo.MainActivity"]
        )

    def test_non_axml_is_reported_not_raised(self) -> None:
        with self.assertRaises(ValueError):
            static_apk.parse_axml(b'<?xml version="1.0"?><manifest/>')
        with tempfile.TemporaryDirectory() as tmp:
            bogus = Path(tmp) / "AndroidManifest.xml"
            bogus.write_bytes(b"not xml at all")
            manifest = static_apk.read_manifest(bogus)
        self.assertIsNotNone(manifest.parse_error)


class EntropyAndDexTests(unittest.TestCase):
    def test_entropy_bounds(self) -> None:
        self.assertEqual(static_apk.shannon_entropy(b""), 0.0)
        self.assertEqual(static_apk.shannon_entropy(bytes(range(256))), 8.0)
        self.assertEqual(static_apk.shannon_entropy(b"\x00" * 1000), 0.0)
        self.assertLess(static_apk.shannon_entropy(fixtures.plain_dex_blob()), 7.5)

    def test_plain_dex_is_not_flagged(self) -> None:
        info = static_apk.inspect_dex("classes2.dex", fixtures.plain_dex_blob())
        self.assertFalse(info.looks_encrypted)
        self.assertEqual(info.method_ids, 64)
        self.assertEqual(info.class_defs, 4)

    def test_encrypted_dex_is_flagged_with_a_reason(self) -> None:
        info = static_apk.inspect_dex("classes.dex", fixtures.encrypted_dex_blob())
        self.assertTrue(info.looks_encrypted)
        self.assertIn("file_size", info.note)
        self.assertGreater(info.entropy, 7.5)

    def test_missing_magic_is_flagged(self) -> None:
        info = static_apk.inspect_dex("classes.dex", b"\x00" * 4096)
        self.assertIn("not a DEX", info.note)


class ProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.apk = fixtures.build_manifest_apk(self.root / "demo.apk")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_probe_reports_archive_dex_and_native_libs(self) -> None:
        probe = static_apk.probe_apk(self.apk)
        self.assertIsNone(probe["error"])
        self.assertEqual(probe["file"]["name"], "demo.apk")
        self.assertEqual(len(probe["file"]["sha256"]), 64)

        self.assertEqual(
            {dex["name"] for dex in probe["dex"]}, {"classes.dex", "classes2.dex"}
        )
        self.assertTrue(probe["flags"]["multiple_dex"])
        self.assertTrue(probe["flags"]["encrypted_dex"])
        self.assertTrue(probe["flags"]["has_native_libs"])
        self.assertEqual(probe["flags"]["abis"], ["arm64-v8a", "x86_64"])
        self.assertEqual(len(probe["native_libs"]), 2)
        self.assertEqual(probe["assets"]["count"], 1)
        self.assertTrue(probe["flags"]["has_resources_arsc"])
        self.assertFalse(probe["flags"]["v2_signature_block"])
        self.assertEqual(probe["manifest"]["package"], "com.example.demo")
        self.assertEqual(probe["assets"]["largest"][0]["name"], "assets/payload.bin")
        self.assertEqual(probe["entries"][0]["name"], sorted(
            (entry["name"] for entry in probe["entries"]),
            key=lambda name: -next(
                item["size"] for item in probe["entries"] if item["name"] == name
            ),
        )[0])

    def test_missing_file_is_reported(self) -> None:
        probe = static_apk.probe_apk(self.root / "absent.apk")
        self.assertEqual(probe["error"], "file does not exist")
        findings = heuristics.apk_findings(probe)
        self.assertEqual(findings[0].id, "apk-unreadable")

    def test_not_a_zip_is_reported(self) -> None:
        bogus = self.root / "not.apk"
        bogus.write_bytes(b"not a zip container")
        probe = static_apk.probe_apk(bogus)
        self.assertIn("not an APK", probe["error"])
        self.assertIn("detected unknown", probe["error"])
        self.assertIn("revlab elf", probe["error"])

    def test_handing_triage_a_native_library_names_the_format_and_the_command(self) -> None:
        # The wrong-file case that matters in practice: someone points the APK
        # pass at the .so they just extracted.
        library = self.root / "libfoo.so"
        library.write_bytes(fixtures.build_elf())
        probe = static_apk.probe_apk(library)
        self.assertIn("not an APK", probe["error"])
        self.assertIn("native ELF", probe["error"])
        self.assertIn("revlab elf", probe["error"])
        self.assertIn("revlab ghidra summary", probe["error"])

    def test_handing_triage_a_windows_exe_names_the_ghidra_command(self) -> None:
        exe = self.root / "app.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 256)
        probe = static_apk.probe_apk(exe)
        self.assertIn("not an APK", probe["error"])
        self.assertIn("PE/COFF", probe["error"])
        self.assertIn("revlab ghidra summary", probe["error"])

    def test_findings_cover_packer_manifest_and_native(self) -> None:
        findings = heuristics.apk_findings(static_apk.probe_apk(self.apk))
        ids = {finding.id for finding in findings}
        for expected in (
            "dex-encrypted-body",
            "high-entropy-payload",
            "manifest-debuggable",
            "manifest-cleartext-true",
            "manifest-sensitive-permissions",
            "native-surface",
            "multiple-dex",
            "no-signature",
        ):
            self.assertIn(expected, ids)
        self.assertIn("critical", {finding.severity for finding in findings})
        encrypted = next(f for f in findings if f.id == "dex-encrypted-body")
        self.assertIn("classes.dex", encrypted.evidence)

    def test_extract_members_refuses_path_traversal(self) -> None:
        evil = self.root / "evil.apk"
        with zipfile.ZipFile(evil, "w") as archive:
            archive.writestr("lib/x86_64/libgood.so", fixtures.build_elf())
            archive.writestr("../escaped.txt", b"nope")
            archive.writestr("/absolute.txt", b"nope")

        dest = self.root / "out"
        written = static_apk.extract_members(evil, ("lib/*/*.so",), dest)
        self.assertEqual([path.name for path in written], ["libgood.so"])
        self.assertFalse((dest / "escaped.txt").exists())
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertTrue((dest / "lib" / "x86_64" / "libgood.so").is_file())

    def test_extract_single_member_by_name(self) -> None:
        dest = self.root / "one"
        written = static_apk.extract_members(
            self.apk, (), dest, single_member="classes2.dex"
        )
        self.assertEqual([path.name for path in written], ["classes2.dex"])
        self.assertFalse((dest / "classes.dex").exists())


if __name__ == "__main__":
    unittest.main()
