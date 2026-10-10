"""Environment check: what is installed, what is missing, what to do about it.

This is the first command a new user runs, so every item carries the *fix* and
not only the failure. It is also the fastest way to diagnose the two mistakes
that cost the most time: a JDK that Ghidra refuses (it needs >= 21) and a
frida-server whose version does not match the frida binding.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from pathlib import Path

from .config import Config

REQUIRED_PYTHON = (3, 9)
MIN_JDK = 21


def _check(name: str, ok: bool, detail: str, hint: str = "", severity: str = "warn") -> dict:
    return {
        "name": name,
        "ok": bool(ok),
        "detail": detail,
        "hint": "" if ok else hint,
        "severity": "ok" if ok else severity,
    }


def _java_binary(folder: Path) -> Path | None:
    """The ``java`` executable inside a JDK home *or* a bin directory."""
    for rel in ("java.exe", "java", "bin/java.exe", "bin/java"):
        candidate = folder / rel
        if candidate.exists():
            return candidate
    return None


def _java_folders(java_home: Path | None) -> list[Path]:
    """Directories worth probing: the configured JDK, then every PATH entry.

    Only the *first* ``java`` on PATH is what a plain PATH lookup returns, and on
    a machine that has ever had a JRE installed that first hit is often an old
    Oracle launcher shim (Java 8/16) sitting in front of a perfectly good JDK
    further down the PATH. Ghidra's own launcher searches for a *suitable* JDK,
    so probing one entry and calling the toolchain broken is a false alarm.
    """
    folders: list[Path] = []
    if java_home is not None:
        folders.append(java_home)
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry.strip():
            folders.append(Path(entry))
    unique: list[Path] = []
    seen: set[str] = set()
    for folder in folders:
        key = str(folder).lower()
        if key not in seen:
            seen.add(key)
            unique.append(folder)
    return unique


def _probe_java(binary: Path) -> tuple[str, int | None]:
    """Run ``java -version`` and parse the major version out of the banner."""
    try:
        completed = subprocess.run(  # noqa: S603
            [str(binary), "-version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "", None
    output = (completed.stderr or "") + (completed.stdout or "")
    match = re.search(r'version "(\d+)(?:\.(\d+))?', output)
    if not match:
        return "", None
    major = int(match.group(1))
    if major == 1 and match.group(2):  # legacy "1.8.0_201" form
        major = int(match.group(2))
    first_line = output.splitlines()[0].strip() if output.strip() else str(binary)
    return first_line, major


def java_versions(java_home: Path | None = None) -> list[dict]:
    """Every JDK Ghidra could start with, newest first.

    Each entry is ``{"path", "line", "major"}``. Sorting newest-first is what
    makes this useful: Ghidra's launcher picks a suitable JDK, not the first one
    the shell happens to resolve.
    """
    found: list[dict] = []
    seen: set[str] = set()
    for folder in _java_folders(java_home):
        binary = _java_binary(folder)
        if binary is None:
            continue
        key = str(binary).lower()
        if key in seen:
            continue
        seen.add(key)
        line, major = _probe_java(binary)
        if major is None:
            continue
        found.append({"path": str(binary), "line": line, "major": major})
    found.sort(key=lambda item: item["major"], reverse=True)
    return found


def java_version(java_home: Path | None = None) -> tuple[str, int | None]:
    """Version line and major of the best JDK available, for callers that only
    want the headline number."""
    found = java_versions(java_home)
    if not found:
        return "", None
    return found[0]["line"], found[0]["major"]


def run_doctor(config: Config) -> dict:
    checks: list[dict] = []
    toolchain = config.toolchain

    checks.append(
        _check(
            "python",
            sys.version_info >= REQUIRED_PYTHON,
            f"{platform.python_version()} on {platform.platform()}",
            f"need Python >= {'.'.join(map(str, REQUIRED_PYTHON))}",
            severity="error",
        )
    )
    checks.append(
        _check(
            "config file",
            config.config_path is not None,
            str(config.config_path) if config.config_path else "no revlab.toml (defaults in use)",
            "copy revlab.toml.example to revlab.toml and set [paths] + [scope]",
        )
    )
    checks.append(_check("workspace", True, str(config.workspace_root)))

    # --- static side --------------------------------------------------------
    headless = toolchain.analyze_headless
    checks.append(
        _check(
            "ghidra install",
            headless is not None,
            str(headless) if headless else f"not found (install dir: {toolchain.ghidra_install})",
            "set [paths] ghidra_install to the Ghidra installation directory",
            severity="error",
        )
    )
    server = toolchain.mcp_server_script
    checks.append(
        _check(
            "ghidra MCP server",
            server is not None,
            str(server) if server else f"not found under {toolchain.ghidra_mcp_root}",
            "set [paths] ghidra_mcp_root to the checkout containing server.py",
            severity="error",
        )
    )
    checks.append(
        _check(
            "ghidra MCP venv",
            toolchain.ghidra_python is not None,
            str(toolchain.ghidra_python) if toolchain.ghidra_python else "no .venv/Scripts/python.exe",
            "create that venv and install PyGhidra + jpype (see docs/02-environment.md)",
        )
    )

    javas = java_versions(toolchain.jdk_home)
    best = javas[0] if javas else None
    if best is None:
        jdk_detail = "no java found in [paths] jdk_home or anywhere on PATH"
    else:
        jdk_detail = f"{best['line']} (major={best['major']}) at {best['path']}"
        stale = [item for item in javas if item["major"] < MIN_JDK]
        if stale:
            jdk_detail += "; older java also on PATH: " + ", ".join(
                f"{item['major']} at {item['path']}" for item in stale[:3]
            )
    checks.append(
        _check(
            "jdk for ghidra",
            best is not None and best["major"] >= MIN_JDK,
            jdk_detail,
            f"Ghidra 12 needs JDK >= {MIN_JDK}. Install one and point [paths] jdk_home "
            "at it -- note that Ghidra's launcher searches PATH itself, so an old "
            "'java' first on PATH is usually harmless, while an old JAVA_HOME is not.",
            severity="error",
        )
    )
    checks.append(_java_home_check())
    return _dynamic_checks(config, checks)


def _java_home_check() -> dict:
    """A JAVA_HOME pointing at a vanished JDK is a classic Ghidra launch failure."""
    value = os.environ.get("JAVA_HOME", "").strip()
    if not value:
        return _check("JAVA_HOME", True, "not set (Ghidra searches PATH)")
    home = Path(value)
    binary = _java_binary(home)
    if binary is None:
        return _check(
            "JAVA_HOME",
            False,
            f"{value} (no java executable inside)",
            "JAVA_HOME points at a JDK that is not there any more; Ghidra's launcher "
            "fails on it before it looks anywhere else. Clear it or point it at a real "
            f"JDK >= {MIN_JDK}.",
        )
    line, major = _probe_java(binary)
    return _check("JAVA_HOME", True, f"{value} ({line or 'java present'})")


def _dynamic_checks(config: Config, checks: list[dict]) -> dict:
    from .frida_dyn import adb_devices, installed_frida_version, list_hooks, server_binaries

    toolchain = config.toolchain
    checks.append(
        _check(
            "frida venv",
            toolchain.frida_python is not None,
            str(toolchain.frida_python) if toolchain.frida_python else "no .venv under frida_root",
            "set [paths] frida_root and create its venv (requirements-frida.txt)",
        )
    )
    frida_version = installed_frida_version(config)
    checks.append(
        _check(
            "frida binding",
            bool(frida_version),
            frida_version or "not importable in the configured venv",
            "install frida + frida-tools into the Frida venv",
        )
    )
    binaries = server_binaries(config)
    checks.append(
        _check(
            "frida-server binaries",
            bool(binaries),
            ", ".join(entry["name"] for entry in binaries) or "none extracted",
            "unpack frida-server-*.xz into <frida_root>/server (Windows has no built-in xz)",
        )
    )
    mismatch = [
        entry["name"]
        for entry in binaries
        if frida_version and entry["version"] and entry["version"] != frida_version
    ]
    checks.append(
        _check(
            "frida version match",
            bool(binaries) and not mismatch,
            (
                f"binding {frida_version} vs server {binaries[-1]['version']}"
                if binaries and frida_version
                else "cannot compare (missing binding or server)"
            ),
            "frida-server must match the binding exactly; mismatched files: "
            + (", ".join(mismatch) or "<none>"),
            severity="error",
        )
    )
    adb_path = toolchain.adb
    checks.append(
        _check(
            "adb",
            adb_path is not None,
            str(adb_path) if adb_path else "not found",
            "set [paths] android_sdk, or keep platform-tools inside frida_root",
        )
    )
    if adb_path is not None:
        try:
            devices = adb_devices(config)
            detail = (
                ", ".join(f"{item['serial']} ({item['state']})" for item in devices) or "no device"
            )
        except Exception as exc:  # noqa: BLE001 - report it, never crash the doctor
            detail = f"adb failed: {exc}"
        checks.append(
            _check(
                "attached devices",
                "no device" not in detail,
                detail,
                "start the emulator/device and enable adb debugging",
            )
        )

    hooks = list_hooks()
    checks.append(
        _check(
            "hook catalogue",
            bool(hooks),
            ", ".join(hook.name for hook in hooks) or "no .js hooks found",
            "hooks ship inside the package (revlab/hooks); reinstall if missing",
            severity="error",
        )
    )
    checks.append(
        _check(
            "authorisation scope",
            bool(config.authorised),
            f"{len(config.authorised)} entry/entries",
            "list the targets you may analyse under [scope] authorised",
            severity="error",
        )
    )

    failed = [item for item in checks if not item["ok"]]
    return {
        "checks": checks,
        "ok": not any(item["severity"] == "error" for item in failed),
        "failed": len(failed),
        "toolchain": toolchain.as_dict(),
        "notes": [
            "errors block the corresponding pass; warnings only reduce coverage",
            "never point the dynamic pass at software you are not allowed to test",
        ],
    }


def format_doctor(report: dict) -> str:
    lines = ["RevLab environment check", "-" * 62]
    for item in report["checks"]:
        mark = "OK  " if item["ok"] else ("FAIL" if item["severity"] == "error" else "WARN")
        lines.append(f"[{mark}] {item['name']}: {item['detail']}")
        if item["hint"]:
            lines.append(f"        -> {item['hint']}")
    lines.append("-" * 62)
    lines.append("result: " + ("ready" if report["ok"] else "blockers present"))
    return "\n".join(lines)
