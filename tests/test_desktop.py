"""The desktop shell, tested without a window.

Everything here runs headless on purpose: the window itself is verified by
``scripts/gui_smoke.py`` (which builds the real widgets and clicks the real
buttons), while the parts that decide *what happens* -- configuration bootstrap,
format sniffing, plan selection, the work function a button calls -- are plain
functions and are tested as such.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
import unittest.mock
import zipfile
from pathlib import Path

from revlab import desktop
from revlab.config import load_config

from . import fixtures


class PathAndLogTests(unittest.TestCase):
    def test_app_dir_and_log_path_are_absolute(self) -> None:
        self.assertTrue(desktop.app_dir().is_absolute())
        self.assertTrue(desktop.log_path().is_absolute())
        self.assertEqual(desktop.log_path().name, desktop.LOG_NAME)

    def test_sample_dir_is_writable(self) -> None:
        target = desktop.sample_dir()
        self.assertTrue(target.is_dir())
        probe = target / ".probe"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()

    def test_redirect_output_sends_prints_to_the_log(self) -> None:
        original = sys.stdout, sys.stderr
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "logs" / "desktop.log"
            with unittest.mock.patch.object(desktop, "log_path", return_value=target):
                try:
                    returned = desktop.redirect_output()
                    print("hello from the windowed build")
                finally:
                    replaced = sys.stdout
                    sys.stdout, sys.stderr = original
                    replaced.close()
            self.assertEqual(returned, target)
            self.assertIn("hello from the windowed build",
                          target.read_text(encoding="utf-8"))


class BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_explicit_config_is_used_as_given(self) -> None:
        path = self.root / "revlab.toml"
        path.write_text('[workspace]\nroot = "ws"\n[scope]\nauthorised = ["x"]\n',
                        encoding="utf-8")
        config, chosen, notes = desktop.bootstrap_config(path)
        self.assertEqual(chosen, path)
        self.assertEqual(config.authorised, ["x"])
        self.assertTrue(notes)

    def test_first_run_writes_a_config_next_to_the_program(self) -> None:
        target = self.root / "cfg" / "revlab.toml"
        with unittest.mock.patch.object(desktop, "default_config_path",
                                        return_value=target):
            config, chosen, notes = desktop.bootstrap_config()
        self.assertTrue(target.exists())
        self.assertEqual(chosen, target)
        self.assertEqual(config.authorised, [])          # default-deny
        self.assertTrue(any("首次运行" in note for note in notes))
        self.assertEqual(load_config(target).mcp_transport, "stdio")


class SniffAndPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_apk_is_recognised_by_its_contents_not_its_name(self) -> None:
        weird = fixtures.build_manifest_apk(self.root / "no-extension-at-all")
        self.assertEqual(desktop.sniff_kind(weird), "apk")
        self.assertEqual(desktop.plan_for(weird).stage, "apk")

    def test_elf_and_pe_and_plain_zip_are_told_apart(self) -> None:
        elf = self.root / "libfoo.so"
        elf.write_bytes(fixtures.build_elf())
        self.assertEqual(desktop.plan_for(elf).stage, "elf")

        pe = self.root / "thing.exe"
        pe.write_bytes(b"MZ" + bytes(64))
        plan = desktop.plan_for(pe)
        self.assertEqual(plan.kind, "pe")
        self.assertEqual(plan.stage, "ghidra")           # Ghidra reads PE directly

        archive = self.root / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("readme.txt", "not an apk")
        self.assertEqual(desktop.sniff_kind(archive), "zip")
        self.assertEqual(desktop.plan_for(archive).stage, "none")

    def test_missing_file_and_directory(self) -> None:
        plan = desktop.plan_for(self.root / "nope.apk")
        self.assertEqual(plan.stage, "none")
        self.assertIn("不存在", plan.label)
        self.assertEqual(desktop.plan_for(self.root).stage, "elf")  # a directory

    def test_summarise_keeps_it_readable(self) -> None:
        lines = desktop.summarise({
            "target": "demo.apk",
            "flags": {"encrypted_dex": True, "abis": ["x86_64", "arm64-v8a"]},
            "facts": [{"a": 1}, {"b": 2}],
        })
        self.assertIn("target: demo.apk", lines)
        self.assertIn("flags:", lines)
        self.assertIn("  encrypted_dex: True", lines)
        self.assertIn("  abis: 2 item(s) [x86_64, arm64-v8a]", lines)
        self.assertIn("facts: 2 item(s)", lines)


class NetworkHelperTests(unittest.TestCase):
    def test_lan_address_looks_like_an_address(self) -> None:
        parts = desktop.lan_address().split(".")
        self.assertEqual(len(parts), 4)
        self.assertTrue(all(part.isdigit() for part in parts))

    def test_free_port_answers_with_a_port(self) -> None:
        port = desktop.free_port()
        self.assertGreater(port, 0)
        self.assertLess(port, 65536)


class RunPlanTests(unittest.TestCase):
    """The function behind the 开始分析 button, called without any widgets."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_file = self.root / "revlab.toml"
        self.config_file.write_text(
            f'[workspace]\nroot = "{(self.root / "workspaces").as_posix()}"\n'
            '[scope]\nauthorised = ["demo.apk"]\n',
            encoding="utf-8",
        )
        self.config = load_config(self.config_file)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_an_apk_produces_a_workspace_and_findings(self) -> None:
        from revlab.pipeline import session_for

        apk = fixtures.build_manifest_apk(self.root / "demo.apk")
        plan = desktop.plan_for(apk)
        workspace, result = desktop.run_plan(self.config, plan, apk)
        self.assertIsNotNone(workspace)
        self.assertTrue((workspace / "session.json").exists())
        self.assertEqual(result["target"], str(apk))
        self.assertGreaterEqual(result["findings"], 5)
        # the encrypted DEX body the sample ships must land as a critical finding
        severities = [item["severity"]
                      for item in session_for(self.config, str(workspace)).findings]
        self.assertIn("critical", severities)

    def test_an_unknown_format_reports_instead_of_running(self) -> None:
        target = self.root / "mystery.bin"
        target.write_bytes(b"\x00\x01\x02\x03")
        plan = desktop.plan_for(target)
        workspace, result = desktop.run_plan(self.config, plan, target)
        self.assertIsNone(workspace)
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
