"""Config, path resolution and the authorisation gate."""

from __future__ import annotations

import os
import tempfile
import tomllib
import unittest
import unittest.mock
from pathlib import Path

from revlab import doctor
from revlab.config import (
    CONFIG_TEMPLATE,
    Config,
    ConfigError,
    ScopeError,
    load_config,
    set_authorised,
    write_default_config,
)


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, body: str) -> Path:
        path = self.root / "revlab.toml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_loads_paths_scope_and_workspace(self) -> None:
        workspace = self.root / "ws"
        config = load_config(
            self._write(
                f"""
[workspace]
root = "{workspace.as_posix()}"

[paths]
ghidra_install = "{(self.root / 'ghidra').as_posix()}"
frida_root = "{(self.root / 'frida').as_posix()}"

[mcp]
timeout_s = 42

[scope]
authorised = ["com.example.demo", "demo.apk"]
"""
            )
        )
        self.assertEqual(config.workspace_root, workspace)
        self.assertEqual(config.mcp_timeout_s, 42)
        self.assertEqual(config.authorised, ["com.example.demo", "demo.apk"])
        self.assertEqual(
            config.toolchain.ghidra_install, self.root / "ghidra"
        )
        self.assertIsNone(config.toolchain.analyze_headless)  # dir exists but no support/

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(self.root / "nope.toml")

    def test_defaults_when_no_config(self) -> None:
        # `load_config(None)` reads ./revlab.toml from the current directory, so
        # run this from a directory that genuinely has no config.
        import os

        previous = os.getcwd()
        empty = self.root / "empty"
        empty.mkdir()
        os.chdir(empty)
        try:
            config = load_config(None)
        finally:
            os.chdir(previous)

        self.assertEqual(config.authorised, [])
        self.assertIsNone(config.config_path)
        self.assertEqual(config.workspace_root, empty / "workspaces")
        self.assertEqual(config.projects_dir(), config.workspace_root / "_ghidra_projects")

    def test_scope_gate_refuses_unknown_target(self) -> None:
        config = Config(authorised=["com.example.demo", "demo.apk"])
        config.require_authorised("com.example.demo")            # package name
        config.require_authorised("C:\\samples\\demo.apk")        # file name fragment
        with self.assertRaises(ScopeError):
            config.require_authorised("com.other.app")

    def test_empty_scope_refuses_everything(self) -> None:
        config = Config(authorised=[])
        with self.assertRaises(ScopeError) as ctx:
            config.require_authorised("com.example.demo")
        self.assertIn("no authorised targets", str(ctx.exception))

    def test_scope_matching_is_case_insensitive_and_substring(self) -> None:
        config = Config(authorised=["Demo.APK"])
        self.assertTrue(config.is_authorised("c:\\samples\\demo.apk"))
        self.assertFalse(config.is_authorised("c:\\samples\\other.apk"))

    def test_workspace_for_is_stable_and_filesystem_safe(self) -> None:
        config = Config(workspace_root=self.root / "ws")
        first = config.workspace_for("c:\\samples\\My App v2.apk")
        second = config.workspace_for("c:\\samples\\My App v2.apk")
        self.assertEqual(first, second)
        self.assertTrue(first.name.endswith("-" + first.name.split("-")[-1]))
        self.assertNotIn(" ", first.name)
        self.assertNotEqual(first, config.workspace_for("c:\\other\\My App v2.apk"))

    def test_config_saved_by_a_windows_editor_with_a_bom_still_loads(self) -> None:
        # Notepad's "UTF-8 with BOM" and PowerShell 5.1's `Set-Content -Encoding
        # utf8` both prepend EF BB BF; the tool must not care.
        path = self.root / "revlab.toml"
        path.write_bytes(
            b"\xef\xbb\xbf"
            + b"[scope]\nauthorised = [\"demo.apk\"]\n"
        )
        config = load_config(path)
        self.assertEqual(config.authorised, ["demo.apk"])

    def test_broken_toml_reports_configerror_not_a_traceback(self) -> None:
        path = self._write("[scope\nauthorised = [\"demo.apk\"]\n")  # missing ']'
        with self.assertRaises(ConfigError) as ctx:
            load_config(path)
        message = str(ctx.exception)
        self.assertIn("not valid TOML", message)
        self.assertIn("hint:", message)

    def test_windows_paths_as_literal_strings_load(self) -> None:
        # The hint in the error message tells operators to use 'C:\dir'; that has
        # to actually work, or the hint is worse than nothing.
        path = self.root / "revlab.toml"
        path.write_text(
            "[paths]\nghidra_install = 'C:\\ghidra'\n",
            encoding="utf-8",
        )
        config = load_config(path)
        self.assertEqual(config.toolchain.ghidra_install, Path("C:/ghidra"))


class JdkDiscoveryTests(unittest.TestCase):
    """`doctor` must not call the toolchain broken because of one stale PATH entry.

    Real case this locks down: PATH resolves `java` to an old Oracle launcher
    shim (Java 16) that shadows a working JDK further down; Ghidra's own launcher
    picks the good one and analyses binaries happily.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._environ: dict[str, str] = {}
        self._saved_path = os.environ.get("PATH", "")

    def tearDown(self) -> None:
        os.environ["PATH"] = self._saved_path
        self.tmp.cleanup()

    def _fake_java(self, folder: str) -> Path:
        binary_dir = self.root / folder / "bin"
        binary_dir.mkdir(parents=True)
        if os.name == "nt":
            binary = binary_dir / "java.exe"
            binary.write_bytes(b"")  # never executed: _probe_java is stubbed
        else:
            binary = binary_dir / "java"
            binary.write_text("#!/bin/sh\n", encoding="utf-8")
            binary.chmod(0o755)
        return binary

    def test_best_jdk_wins_even_when_an_older_java_comes_first_on_path(self) -> None:
        stale = self._fake_java("jre16")
        good = self._fake_java("jdk25")

        def fake_probe(binary: Path) -> tuple[str, int | None]:
            if str(binary) == str(stale):
                return ('java version "16" 2021-03-16', 16)
            if str(binary) == str(good):
                return ('openjdk version "25.0.4.1" 2026-08-18 LTS', 25)
            return "", None

        os.environ["PATH"] = os.pathsep.join([str(stale.parent), str(good.parent)])
        with unittest.mock.patch.object(doctor, "_probe_java", fake_probe):
            found = doctor.java_versions()
            line, major = doctor.java_version()

        self.assertEqual([item["major"] for item in found], [25, 16])
        self.assertEqual(found[0]["path"], str(good))
        self.assertEqual(major, 25)
        self.assertIn("25", line)

    def test_no_java_anywhere_is_reported_rather_than_guessed(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        os.environ["PATH"] = str(empty)
        with unittest.mock.patch.object(doctor, "_probe_java", lambda binary: ("", None)):
            self.assertEqual(doctor.java_versions(), [])
        self.assertEqual(doctor.java_version(), ("", None))

    def test_a_broken_java_home_is_called_out(self) -> None:
        missing = self.root / "jdk-gone"
        os.environ["JAVA_HOME"] = str(missing)
        try:
            check = doctor._java_home_check()
        finally:
            os.environ.pop("JAVA_HOME", None)
        self.assertFalse(check["ok"])
        self.assertIn("no java executable", check["detail"])
        self.assertIn("Ghidra", check["hint"])


class AuthorisedRewriteTests(unittest.TestCase):
    """The desktop app edits ``[scope]`` in the file, so the edit must be surgical.

    It replaces one value and leaves the operator's comments, layout and every
    other table alone -- and it re-reads what actually landed on disk, because
    "valid in memory" is not the same as "valid in the file" on Windows.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, body: str) -> Path:
        path = self.root / "revlab.toml"
        path.write_bytes(body.encode("utf-8"))
        return path

    @staticmethod
    def _scope(path: Path) -> list[str]:
        return tomllib.loads(path.read_bytes().decode("utf-8-sig"))["scope"]["authorised"]

    def test_adds_the_scope_table_when_it_is_missing(self) -> None:
        path = self._write('[workspace]\nroot = ""\n\n[paths]\nghidra_install = ""\n')
        written = set_authorised(path, ["demo.apk"])
        text = path.read_bytes().decode("utf-8")
        self.assertEqual(written, ["demo.apk"])
        self.assertIn("[scope]", text)
        self.assertIn('[paths]', text)
        self.assertEqual(self._scope(path), ["demo.apk"])

    def test_replaces_one_line_and_keeps_comments_and_neighbours(self) -> None:
        path = self._write(
            "# top comment\n"
            '[paths]\nghidra_install = ""\n\n'
            "# a comment about scope\n"
            '[scope]\n'
            'authorised = ["old.apk"]\n\n'
            '[frida]\nserial = ""\n'
        )
        set_authorised(path, ["new.apk", "com.example.other"])
        text = path.read_bytes().decode("utf-8")
        self.assertIn("# top comment", text)
        self.assertIn("# a comment about scope", text)
        self.assertIn('ghidra_install = ""', text)
        self.assertIn('[frida]\nserial = ""', text.replace("\r\n", "\n"))
        self.assertNotIn("old.apk", text)
        self.assertEqual(self._scope(path), ["new.apk", "com.example.other"])

    def test_replaces_a_multi_line_list_without_eating_the_next_table(self) -> None:
        path = self._write(
            "[scope]\n"
            "authorised = [\n"
            '  # "com.example.demo",\n'
            '  # "demo.apk",\n'
            "]\n"
            "\n[frida]\nserial = \"abc\"\n"
        )
        set_authorised(path, ["com.example.demo"])
        data = tomllib.loads(path.read_bytes().decode("utf-8-sig"))
        self.assertEqual(data["scope"]["authorised"], ["com.example.demo"])
        self.assertEqual(data["frida"]["serial"], "abc")

    def test_empty_list_and_long_list_are_both_valid(self) -> None:
        path = self._write('[scope]\nauthorised = ["a"]\n')
        set_authorised(path, [])
        self.assertEqual(self._scope(path), [])
        self.assertIn("authorised = []", path.read_bytes().decode("utf-8"))

        many = [f"target-{index}.apk" for index in range(6)]
        set_authorised(path, many)
        self.assertEqual(self._scope(path), many)
        self.assertIn("authorised = [\n", path.read_bytes().decode("utf-8"))

    def test_backup_holds_the_previous_file_and_writing_twice_is_stable(self) -> None:
        path = self._write('[scope]\nauthorised = ["first.apk"]\n')
        original = path.read_bytes()
        set_authorised(path, ["second.apk"])
        self.assertEqual((self.root / "revlab.toml.bak").read_bytes(), original)

        once = path.read_bytes()
        set_authorised(path, ["second.apk"])
        self.assertEqual(path.read_bytes(), once)

    def test_what_lands_on_disk_parses(self) -> None:
        # A Windows text-mode write would turn "\r\n" into "\r\r\n" here and make
        # the file unreadable to tomllib; this is the regression guard for that.
        path = self._write('[scope]\r\nauthorised = ["a"]\r\n')
        set_authorised(path, ["b"])
        raw = path.read_bytes()
        self.assertNotIn(b"\r\r", raw)
        self.assertEqual(self._scope(path), ["b"])
        self.assertIsNotNone(load_config(path).authorised)

    def test_default_template_and_example_do_not_drift(self) -> None:
        def keys(body: str) -> set:
            data = tomllib.loads(body)
            return {
                (section, key)
                for section, values in data.items()
                if isinstance(values, dict)
                for key in values
            }

        example = (Path(__file__).resolve().parents[1] / "revlab.toml.example")
        self.assertEqual(keys(CONFIG_TEMPLATE), keys(example.read_bytes().decode("utf-8-sig")))

    def test_write_default_config_produces_a_loadable_file(self) -> None:
        path = write_default_config(self.root / "nested" / "revlab.toml")
        config = load_config(path)
        self.assertEqual(config.authorised, [])
        self.assertEqual(config.mcp_transport, "stdio")


if __name__ == "__main__":
    unittest.main()
