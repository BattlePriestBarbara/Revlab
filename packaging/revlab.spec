# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller recipe for the desktop build.

Two executables come out of one analysis -- ``RevLab.exe`` (windowed, the
double-clickable app) and ``RevLabCLI.exe`` (console, the same commands as
``python -m revlab``) -- plus the shared files the program reads at runtime: the
Frida hook scripts, the Ghidra post-script, the config template, docs.

The core is standard library only, so there is no dependency to freeze: whatever
frida / the MCP SDK contribute is collected only when those are installed in the
build environment, and both engines already fail with a readable message when
they are missing.

    pyinstaller --noconfirm --clean packaging/revlab.spec
    $env:REVLAB_ONEFILE = "1"   # also emit single-file RevLab-Portable.exe
"""

import os
from pathlib import Path

ROOT = Path(SPECPATH).parent
ICON = ROOT / "packaging" / "revlab.ico"
ONEFILE = os.environ.get("REVLAB_ONEFILE") == "1"

datas = [
    (str(ROOT / "revlab" / "hooks"), "revlab/hooks"),
    (str(ROOT / "revlab" / "ghidra_scripts"), "revlab/ghidra_scripts"),
    (str(ROOT / "revlab.toml.example"), "."),
    (str(ROOT / "README.md"), "."),
]
if (ROOT / "docs").is_dir():
    datas.append((str(ROOT / "docs"), "docs"))

a = Analysis(
    [
        str(ROOT / "packaging" / "entry_gui.py"),
        str(ROOT / "packaging" / "entry_cli.py"),
    ],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        # The window needs Tk, and Tk needs its data files (tcl8.6 / tk8.6, the
        # `tcl8` module tree, the encodings). Naming the tkinter modules here
        # keeps all of it in the graph on purpose rather than by luck of the
        # import scan; `_tkinter` is the extension that pulls in the Tcl/Tk data
        # through PyInstaller's hook.
        "tkinter",
        "tkinter.filedialog",
        "tkinter.messagebox",
        "tkinter.ttk",
        "_tkinter",
        "revlab.desktop",
        "revlab.webui",
        "revlab.frida_dyn",
        "revlab.ghidra",
        "revlab.mcp_client",
        "revlab.mcp_server",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "numpy", "pandas", "matplotlib", "PIL"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

# ---------------------------------------------------------------------------
# Tcl/Tk: collected is not the same as findable.
#
# `hook-_tkinter` puts the libraries into the collection as `_tcl_data` /
# `_tk_data`, and PyInstaller's run-time hook `pyi_rth__tkinter` is what points
# `TCL_LIBRARY` / `TK_LIBRARY` at them. Miss either half and the frozen window
# dies on start with
#
#     _tkinter.TclError: Can't find a usable init.tcl in the following
#     directories:  <dist>\lib\tcl8.6 <dist>\library ...
#
# Both halves are checked here, at build time, because the failure only shows up
# when a human double-clicks the result.
# ---------------------------------------------------------------------------
TCL_TK_PAYLOAD = ("_tcl_data/init.tcl", "_tk_data/tk.tcl")


def _destinations(datas) -> list:
    """Every destination name in a collection, with one separator."""
    return [str(entry[0]).replace("\\", "/") for entry in datas]


def _script_name(entry) -> str:
    """How PyInstaller stores a script: a path, or a bare module name."""
    return Path(str(entry[0])).name


def missing_tcl_tk(datas) -> list:
    """The Tcl/Tk library files that did not make it into the collection."""
    names = _destinations(datas)
    return [wanted for wanted in TCL_TK_PAYLOAD
            if not any(name.endswith(wanted) for name in names)]


_missing = missing_tcl_tk(a.datas)
print(f"[revlab.spec] tcl/tk payload   : "
      f"{'ok' if not _missing else 'MISSING -> ' + ', '.join(_missing)}")
if _missing:
    raise SystemExit(
        "ERROR: the Tcl/Tk libraries were not collected (" + ", ".join(_missing) + ").\n"
        "       PyInstaller's hook-_tkinter.py needs a working tkinter in the build\n"
        '       environment: check `python -c "import tkinter; tkinter.Tk()"` with the\n'
        "       interpreter that is running this build."
    )


def payload_sources(datas) -> dict:
    """Where the collected Tcl/Tk library files came from."""
    sources = {}
    for entry in datas:
        destination = str(entry[0]).replace("\\", "/")
        for wanted in TCL_TK_PAYLOAD:
            if destination.endswith(wanted):
                sources[wanted] = str(entry[1])
    return sources


# PyInstaller asks a *real* Tcl interpreter for `info library`, so an inherited
# TCL_LIBRARY / TK_LIBRARY decides what gets collected. Left over in a shell -- a
# debugging session sets exactly that -- the build harvests its own previous
# output while overwriting it, and the result is a bundle that starts with
# "Can't find a usable init.tcl". scripts\build_exe.ps1 drops those variables;
# this refuses to build if one got through anyway.
_sources = payload_sources(a.datas)
print(f"[revlab.spec] tcl/tk from       : {_sources.get('_tcl_data/init.tcl', '?')}")
_own_output = [str(ROOT / name).lower() for name in ("dist", "build")]
_cannibal = [source for source in _sources.values()
             if any(source.lower().startswith(prefix) for prefix in _own_output)]
if _cannibal:
    raise SystemExit(
        "ERROR: the Tcl/Tk libraries were collected from this project's own build\n"
        f"       output ({_cannibal[0]}).\n"
        "       That means TCL_LIBRARY or TK_LIBRARY is set in the environment\n"
        "       (PyInstaller asks a real Tcl interpreter for `info library`), so the\n"
        "       build would package a copy of its previous result. Unset both, wipe\n"
        "       dist\\, and build again."
    )


def script_for(stem: str, collected: list):
    """Pick this executable's entry script -- and keep every run-time hook.

    PyInstaller appends its run-time hooks (``pyi_rth_*.py``) to
    ``Analysis.scripts`` (see ``build_main.py``: ``self.scripts = rthook_toc +
    program_toc``). Handing an EXE only its entry point silently drops them, and
    the Tk one is not optional: nothing else sets ``TCL_LIBRARY`` for the frozen
    program. The fallback keeps the build working if a future version names the
    entries differently -- it just grows the executable a little.
    """
    hooks = [entry for entry in collected if _script_name(entry).startswith("pyi_rth")]
    own = [entry for entry in collected
           if entry not in hooks and Path(_script_name(entry)).stem == stem]
    return (hooks + own) if own else list(collected)


GUI = script_for("entry_gui", a.scripts)
CLI = script_for("entry_cli", a.scripts)
for _label, _chosen in (("RevLab", GUI), ("RevLabCLI", CLI)):
    print(f"[revlab.spec] {_label:<10} <- {[_script_name(entry) for entry in _chosen]}")

# Windows file properties: "RevLab 0.2.0" in Explorer beats a blank page.
version = None
try:  # pragma: no cover - build-time only
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    version = VSVersionInfo(
        ffi=FixedFileInfo(filevers=(0, 2, 0, 0), prodvers=(0, 2, 0, 0),
                          mask=0x3F, flags=0x0, OS=0x40004, fileType=0x1,
                          subtype=0x0, date=(0, 0)),
        kids=[
            StringFileInfo([
                StringTable("040904B0", [
                    StringStruct("CompanyName", "RevLab"),
                    StringStruct("FileDescription",
                                 "RevLab reverse-engineering workbench"),
                    StringStruct("FileVersion", "0.2.0"),
                    StringStruct("InternalName", "RevLab"),
                    StringStruct("LegalCopyright", "MIT licensed"),
                    StringStruct("OriginalFilename", "RevLab.exe"),
                    StringStruct("ProductName", "RevLab"),
                    StringStruct("ProductVersion", "0.2.0"),
                ]),
            ]),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )
except Exception:  # noqa: BLE001 - a missing resource is not a build failure
    version = None

_icon = str(ICON) if ICON.exists() else None

exe_gui = EXE(
    pyz, GUI, [], exclude_binaries=True, name="RevLab", icon=_icon,
    version=version, console=False, debug=False, strip=False,
    upx=False,  # UPX would trip antivirus heuristics for no real gain
    bootloader_ignore_signals=False, disable_windowed_traceback=False,
    argv_emulation=False, target_arch=None, codesign_identity=None,
    entitlements_file=None,
)
exe_cli = EXE(
    pyz, CLI, [], exclude_binaries=True, name="RevLabCLI", icon=_icon,
    version=version, console=True, debug=False, strip=False, upx=False,
    bootloader_ignore_signals=False, disable_windowed_traceback=False,
    argv_emulation=False, target_arch=None, codesign_identity=None,
    entitlements_file=None,
)
collect = COLLECT(exe_gui, exe_cli, a.binaries, a.datas,
                  strip=False, upx=False, name="RevLab")

if ONEFILE:
    exe_portable = EXE(
        pyz, GUI, a.binaries, a.datas, [],
        name="RevLab-Portable", icon=_icon, version=version, console=False,
        debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    )
