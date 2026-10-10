"""The packaging layer, guarded by reading it.

A build that only lives in someone's shell history rots. These tests keep the
pieces honest without requiring PyInstaller or the Android SDK to be present: the
spec must still name both entry points, the icon must still encode as a real
ICO/PNG, the manifest must still declare a launchable activity with the one
permission the client needs, and the Android sources must still be shaped the way
R8 accepts them here (one top-level class per file -- see MainActivity.java).
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import struct
import sys
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "android"
PACKAGING = ROOT / "packaging"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def load_script(name: str):
    """Import a helper script by path: they are tools, not package modules."""
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)
    return module


class SpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = (PACKAGING / "revlab.spec").read_text(encoding="utf-8")

    def test_the_spec_is_valid_python_and_names_both_programs(self) -> None:
        compile(self.spec, "revlab.spec", "exec")
        for needle in ("entry_gui", "entry_cli", "RevLabCLI", "RevLab-Portable",
                       "revlab/hooks", "revlab/ghidra_scripts",
                       "revlab.toml.example", "REVLAB_ONEFILE"):
            self.assertIn(needle, self.spec)

    def test_entry_points_import_the_real_mains(self) -> None:
        gui = (PACKAGING / "entry_gui.py").read_text(encoding="utf-8")
        cli = (PACKAGING / "entry_cli.py").read_text(encoding="utf-8")
        self.assertIn("from revlab.desktop import main", gui)
        self.assertIn("from revlab.cli import main", cli)

        from revlab import cli as cli_module
        from revlab import desktop as desktop_module

        self.assertTrue(callable(cli_module.main))
        self.assertTrue(callable(desktop_module.main))


def fake_scripts() -> list:
    """What ``Analysis.scripts`` looks like: run-time hooks first, then entries."""
    pyinstaller = "C:/Python312/Lib/site-packages/PyInstaller"
    return [
        ("pyi_rth__tkinter", f"{pyinstaller}/hooks/rthooks/pyi_rth__tkinter.py"),
        ("pyi_rth_pkgutil", f"{pyinstaller}/loader/pyi_rth_pkgutil.py"),
        (f"{ROOT}/packaging/entry_gui.py", f"{ROOT}/packaging/entry_gui.py"),
        (f"{ROOT}/packaging/entry_cli.py", f"{ROOT}/packaging/entry_cli.py"),
    ]


class SpecTclTkTests(unittest.TestCase):
    """The frozen window must be able to *find* Tcl/Tk, not merely carry it.

    PyInstaller appends its run-time hooks (``pyi_rth_*.py``) to
    ``Analysis.scripts``. A spec that hands an EXE only its entry point drops them
    without a word -- and the Tk hook is what sets ``TCL_LIBRARY``, so the window
    died with "Can't find a usable init.tcl" while every Tcl/Tk file was already in
    the bundle. These tests run the real spec against stub builders and inspect
    what each executable was actually given.
    """

    def run_spec(self, scripts: list, datas: list | None = None) -> dict:
        captured: dict = {"exe": {}}
        payload = [("_tcl_data/init.tcl", "C:/Python312/tcl/tcl8.6/init.tcl"),
                   ("_tk_data/tk.tcl", "C:/Python312/tcl/tk8.6/tk.tcl")]

        class FakeAnalysis:
            def __init__(self, *args, **kwargs):
                self.pure = []
                self.scripts = scripts
                self.binaries = []
                self.datas = payload if datas is None else datas

        class FakePYZ:
            def __init__(self, *args, **kwargs):
                pass

        def fake_exe(*args, **kwargs):
            captured["exe"][kwargs["name"]] = list(args[1])
            return object()

        namespace = {
            "Analysis": FakeAnalysis,
            "PYZ": FakePYZ,
            "EXE": fake_exe,
            "COLLECT": lambda *args, **kwargs: object(),
            "SPECPATH": str(PACKAGING),
        }
        text = (PACKAGING / "revlab.spec").read_text(encoding="utf-8")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            exec(compile(text, "revlab.spec", "exec"), namespace)
        captured["stdout"] = stream.getvalue()
        return captured

    @staticmethod
    def names_of(entries: list) -> list:
        return [Path(str(entry[0])).name for entry in entries]

    def test_every_exe_keeps_the_run_time_hooks(self) -> None:
        captured = self.run_spec(fake_scripts())
        self.assertEqual(sorted(captured["exe"]), ["RevLab", "RevLabCLI"])
        for exe, entry in (("RevLab", "entry_gui.py"), ("RevLabCLI", "entry_cli.py")):
            names = self.names_of(captured["exe"][exe])
            self.assertIn(entry, names)
            # runs first, sets TCL_LIBRARY / TK_LIBRARY for the frozen program
            self.assertIn("pyi_rth__tkinter", names)
            self.assertIn("pyi_rth_pkgutil", names)
            self.assertEqual(names[-1], entry, "the entry point must still boot the exe")

    def test_the_portable_build_keeps_them_too(self) -> None:
        with mock.patch.dict(os.environ, {"REVLAB_ONEFILE": "1"}):
            captured = self.run_spec(fake_scripts())
        self.assertIn("RevLab-Portable", captured["exe"])
        self.assertIn("pyi_rth__tkinter", self.names_of(captured["exe"]["RevLab-Portable"]))

    def test_a_collection_without_the_tcl_libraries_fails_the_build(self) -> None:
        # Reproduces the state the .exe was in: Tk itself collected, the library
        # files not. That must stop the build rather than reach a user.
        with self.assertRaises(SystemExit) as caught:
            self.run_spec(fake_scripts(), datas=[("docs/07-packaging.md", "x")])
        self.assertIn("Tcl/Tk", str(caught.exception))

    def test_a_build_that_harvests_its_own_output_is_refused(self) -> None:
        # Setting TCL_LIBRARY in the shell made PyInstaller collect the libraries
        # out of the previous dist\ while overwriting it: 926 files went missing,
        # including init.tcl. The spec must refuse that instead of packaging it.
        cannibal = [("_tcl_data/init.tcl", str(ROOT / "dist" / "RevLab" / "_internal"
                                                 / "_tcl_data" / "init.tcl")),
                    ("_tk_data/tk.tcl", str(ROOT / "dist" / "RevLab" / "_internal"
                                            / "_tk_data" / "tk.tcl"))]
        with self.assertRaises(SystemExit) as caught:
            self.run_spec(fake_scripts(), datas=cannibal)
        self.assertIn("TCL_LIBRARY", str(caught.exception))

    def test_the_spec_reports_what_it_chose(self) -> None:
        captured = self.run_spec(fake_scripts())
        self.assertIn("tcl/tk payload   : ok", captured["stdout"])
        self.assertIn("pyi_rth__tkinter", captured["stdout"])


class IconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.icon = load_script("make_icon.py")

    def test_raster_is_the_size_asked_for(self) -> None:
        self.assertEqual(len(self.icon.render(16)), 16 * 16 * 4)
        self.assertEqual(len(self.icon.render(48)), 48 * 48 * 4)
        # transparent corners, opaque middle
        pixels = self.icon.render(16)
        self.assertEqual(pixels[3], 0)
        self.assertGreater(max(pixels[index * 4 + 3] for index in range(16 * 16)), 200)

    def test_png_and_ico_encoders_emit_real_headers(self) -> None:
        png = self.icon.png_bytes(self.icon.render(24), 24, 24)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", png[:32])

        ico = self.icon.ico_bytes([(16, self.icon.render(16))])
        self.assertEqual(struct.unpack_from("<HHH", ico, 0), (0, 1, 1))

    def test_the_shipped_icon_and_the_android_icons_are_consistent(self) -> None:
        ico_path = PACKAGING / "revlab.ico"
        self.assertTrue(ico_path.exists(), "run scripts/make_icon.py")
        self.assertEqual(struct.unpack_from("<H", ico_path.read_bytes(), 4)[0],
                         len(self.icon.ICO_SIZES))

        for density, size in self.icon.ANDROID_SIZES.items():
            path = ANDROID / "res" / f"mipmap-{density}" / "ic_launcher.png"
            self.assertTrue(path.exists(), f"missing {path}")
            data = path.read_bytes()
            self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertEqual(struct.unpack_from(">II", data, 16), (size, size))


class AndroidProjectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = ElementTree.parse(ANDROID / "AndroidManifest.xml").getroot()

    def test_the_manifest_declares_a_launchable_activity(self) -> None:
        self.assertEqual(self.manifest.get("package"), "com.revlab.mobile")
        application = self.manifest.find("application")
        self.assertIsNotNone(application)
        self.assertEqual(application.get(ANDROID_NS + "usesCleartextTraffic"), "true")

        permissions = [item.get(ANDROID_NS + "name")
                       for item in self.manifest.findall("uses-permission")]
        self.assertEqual(permissions, ["android.permission.INTERNET"])

        activities = application.findall("activity")
        self.assertEqual(len(activities), 1)
        activity = activities[0]
        self.assertEqual(activity.get(ANDROID_NS + "name"), ".MainActivity")
        self.assertEqual(activity.get(ANDROID_NS + "exported"), "true")
        self.assertIn("android.intent.action.MAIN",
                      [item.get(ANDROID_NS + "name") for item in activity.iter("action")])
        self.assertIn("android.intent.category.LAUNCHER",
                      [item.get(ANDROID_NS + "name") for item in activity.iter("category")])

    def test_the_sources_keep_to_one_top_level_class_per_file(self) -> None:
        # R8 (d8) here aborts on any class file carrying an InnerClasses attribute,
        # so nesting must not creep back in unnoticed.
        sources = sorted((ANDROID / "java").rglob("*.java"))
        self.assertTrue(sources)
        for source in sources:
            text = source.read_text(encoding="utf-8")
            declared = re.findall(r"^(?:public |final |abstract )*class\s+\w+", text, re.M)
            self.assertEqual(len(declared), 1,
                             f"{source.name} must declare exactly one top-level class")
            self.assertIsNone(re.search(r"new\s+[\w.]+\s*\([^()]*\)\s*\{", text),
                              f"{source.name} must not contain an anonymous class")

    def test_the_client_only_reaches_the_network_through_the_dashboard(self) -> None:
        source = (ANDROID / "java" / "com" / "revlab" / "mobile"
                  / "MainActivity.java").read_text(encoding="utf-8")
        # one WebView, one address bar: nothing else is implemented here
        self.assertIn("WebView", source)
        self.assertIn("usesCleartextTraffic", (ANDROID / "AndroidManifest.xml")
                      .read_text(encoding="utf-8"))
        self.assertNotIn("Runtime.getRuntime", source)

    def test_the_build_and_the_diagnostic_agree_about_the_constraint(self) -> None:
        builder = (ANDROID / "build_apk.py").read_text(encoding="utf-8")
        checker = (ANDROID / "check_toolchain.py").read_text(encoding="utf-8")
        for needle in ("InnerClasses", "check_toolchain.py", "apksigner", "zipalign",
                       "com.android.tools.r8.D8", "PKCS12"):
            self.assertIn(needle, builder)
        for needle in ("InnerClasses", "PlainActivity", "Nested", "android.jar"):
            self.assertIn(needle, checker)
        compile(builder, "build_apk.py", "exec")
        compile(checker, "check_toolchain.py", "exec")


class BuildScriptTests(unittest.TestCase):
    def test_the_exe_script_builds_and_then_verifies(self) -> None:
        script = (ROOT / "scripts" / "build_exe.ps1").read_text(encoding="utf-8-sig")
        for needle in (
            "packaging\\revlab.spec",       # what it builds
            "PyInstaller",
            "make_icon.py",
            "gui_smoke_frozen.py",          # how it proves a window came up
            "revlab-desktop.log",           # where to look when it did not
            "TCL_LIBRARY",                  # inherited values it refuses to honour
            "RevLab.lnk",                   # the optional shortcut
            "Test-BasePython",              # refuses an unsupported python
        ):
            self.assertIn(needle, script)
        # A growing log file is not evidence that a window appeared: the log is
        # opened before Tk is created, so a startup traceback grows it too.
        self.assertNotIn("Start-Process", script)

    def test_the_frozen_smoke_test_looks_for_a_real_window(self) -> None:
        text = (ROOT / "scripts" / "gui_smoke_frozen.py").read_text(encoding="utf-8")
        compile(text, "gui_smoke_frozen.py", "exec")
        for needle in ("EnumWindows", "IsWindowVisible",    # a window, not a log line
                       "TCL_LIBRARY", "TK_LIBRARY",         # stripped from the child env
                       "copytree",                          # runs from a copy
                       "revlab-desktop.log"):               # printed when it fails
            self.assertIn(needle, text)

    def test_the_gui_smoke_script_drives_the_real_window(self) -> None:
        text = (ROOT / "scripts" / "gui_smoke.py").read_text(encoding="utf-8")
        compile(text, "gui_smoke.py", "exec")
        for needle in ("desktop.Window", "make_sample", "analyze", "report", "doctor"):
            self.assertIn(needle, text)

    def test_the_demo_generator_uses_the_shipped_builders(self) -> None:
        script = (ROOT / "scripts" / "make_demo_apk.py").read_text(encoding="utf-8")
        self.assertIn("from revlab import demo", script)
        self.assertIn("demo.build_demo_apk(output)", script)


if __name__ == "__main__":
    unittest.main()
