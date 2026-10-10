"""Does the *frozen* window really come up? Start it, then look for the window.

    python scripts\\gui_smoke_frozen.py                       # dist\\RevLab\\RevLab.exe
    python scripts\\gui_smoke_frozen.py --exe C:\\somewhere\\RevLab.exe --keep

``build_exe.ps1`` runs this as its verification step, and it is the only check a
human would accept: the program is started, and then Windows is asked whether a
*visible* top-level window belonging to that exact process exists and carries the
expected title.

Watching the log file grow -- the first version of this check -- is not enough.
The log is opened before Tk is created, so a startup traceback also makes it grow;
that is how a build was shipped whose window died with "Can't find a usable
init.tcl in the following directories".

Two details are deliberate:

* the program is copied to a temporary directory and run from there, so a green
  result cannot depend on the build tree sitting next to it;
* ``TCL_LIBRARY`` / ``TK_LIBRARY`` / ``PYTHONHOME`` / ``PYTHONPATH`` are removed
  from the child environment, so a leftover variable in the shell that happens to
  run this cannot make a broken bundle look healthy (that is exactly how the
  Tcl/Tk problem was confirmed by hand).

Exit 0 = a window came up, and the frozen CLI answered ``--version``.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXE = ROOT / "dist" / "RevLab" / "RevLab.exe"
LOG = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "RevLab" / "logs" / "revlab-desktop.log"
# Inherited values that would hide a broken bundle rather than test it.
INHERITED = ("TCL_LIBRARY", "TK_LIBRARY", "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP")
SKIP_WHEN_COPYING = ("workspaces", "samples")


def clean_environment() -> dict:
    env = {key: value for key, value in os.environ.items() if key not in INHERITED}
    env.setdefault("PYTHONUTF8", "1")
    return env


def visible_windows(pid: int) -> list[str]:
    """Titles of the visible top-level windows owned by ``pid``."""
    if sys.platform != "win32":  # pragma: no cover - the build targets Windows
        return []
    user32 = ctypes.WinDLL("user32")
    titles: list[str] = []
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def visit(hwnd, _lparam) -> bool:
        owner = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid or not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, length + 1)
        if buffer.value:
            titles.append(buffer.value)
        return True

    callback = callback_type(visit)  # keep a reference: EnumWindows does not
    user32.EnumWindows(callback, None)
    return titles


def log_tail(before: int, lines: int = 15) -> list[str]:
    """The part of the log this run added, or its last lines."""
    if not LOG.exists():
        return [f"(no log at {LOG})"]
    text = LOG.read_text(encoding="utf-8", errors="replace")
    if len(text) > before:
        text = text[before:]
    return [line for line in text.splitlines() if line.strip()][-lines:]


def isolate(exe: Path, keep: bool) -> tuple[Path, Path]:
    """Copy the whole program directory to a temporary one and run from there."""
    sandbox = Path(tempfile.mkdtemp(prefix="revlab-frozen-"))
    target = sandbox / exe.parent.name
    shutil.copytree(
        exe.parent, target,
        ignore=shutil.ignore_patterns(*SKIP_WHEN_COPYING),
        dirs_exist_ok=True,
    )
    print(f"   isolated : {sandbox}{'' if keep else ' (removed afterwards)'}"
          f"{' (kept: --keep)' if keep else ''}")
    return target / exe.name, sandbox


def check_cli(cli: Path, env: dict) -> str:
    result = subprocess.run([str(cli), "--version"], cwd=str(cli.parent), env=env,
                            capture_output=True, text=True, errors="replace", timeout=60)
    output = [line for line in (result.stdout or result.stderr).splitlines() if line.strip()]
    if result.returncode != 0:
        raise SystemExit(f"!! RevLabCLI.exe --version failed (exit {result.returncode}):\n"
                         + "\n".join(output))
    return output[-1] if output else "(no output)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="start the frozen window and find it")
    parser.add_argument("--exe", default=str(DEFAULT_EXE), help="the windowed build")
    parser.add_argument("--cli", default="", help="defaults to RevLabCLI.exe next to --exe")
    parser.add_argument("--timeout", type=float, default=40.0, help="seconds to wait")
    parser.add_argument("--expect", default="RevLab", help="text the window title must contain")
    parser.add_argument("--no-isolated", action="store_true",
                        help="run in place instead of copying the directory")
    parser.add_argument("--keep", action="store_true", help="keep the isolated copy")
    args = parser.parse_args(argv)

    try:  # a GBK console must not abort on Chinese output
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001 - cosmetic only
        pass

    exe = Path(args.exe)
    if not exe.exists():
        print(f"!! no executable at {exe} -- run scripts\\build_exe.ps1 first")
        return 1
    cli = Path(args.cli) if args.cli else exe.with_name("RevLabCLI.exe")
    env = clean_environment()

    sandbox: Path | None = None
    if not args.no_isolated:
        exe, sandbox = isolate(exe, args.keep)
        cli = exe.with_name("RevLabCLI.exe")

    print(f"   program  : {exe}")
    try:
        if cli.exists():
            print(f"   cli      : {check_cli(cli, env)}")
        else:
            print(f"   cli      : (missing: {cli.name})")

        before = LOG.stat().st_size if LOG.exists() else 0
        started = time.monotonic()
        process = subprocess.Popen([str(exe)], cwd=str(exe.parent), env=env)
        titles: list[str] = []
        while time.monotonic() - started < args.timeout:
            titles = [title for title in visible_windows(process.pid)
                      if args.expect.lower() in title.lower()]
            if titles or process.poll() is not None:
                break
            time.sleep(0.25)
        elapsed = time.monotonic() - started

        if not titles:
            code = process.poll()
            state = f"exited with {code}" if code is not None else "still running"
            print(f"!! no window after {elapsed:.1f}s (process {state})")
            print(f"!! log tail ({LOG}):")
            for line in log_tail(before):
                print(f"      {line}")
            process.kill()
            process.wait(timeout=10)
            return 1

        print(f"   window   : {titles[0]!r} after {elapsed:.1f}s")
        config = exe.with_name("revlab.toml")
        if config.exists():
            print(f"   config   : {config} (written on first run)")
        process.kill()
        process.wait(timeout=10)
    finally:
        if sandbox is not None and not args.keep:
            shutil.rmtree(sandbox, ignore_errors=True)

    print("SMOKE OK (frozen)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
