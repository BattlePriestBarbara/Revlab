"""Configuration, path discovery and the authorisation gate.

RevLab keeps every machine-specific value in one place (``revlab.toml`` plus
environment variables) and refuses to instrument anything that is not written
down as authorised. The gate is deliberately boring: no prompt to dismiss, no
flag that silently overrides the list -- the operator writes down what they are
allowed to touch, or the dynamic engine stays off.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAME = "revlab.toml"

#: Used by :func:`write_default_config` when ``revlab.toml.example`` is not
#: next to the program (a frozen build may not ship the checkout). A test keeps
#: this and the example file from drifting apart.
CONFIG_TEMPLATE = """\
# RevLab configuration -- written by the desktop app on first run.
# [scope] is the authorisation gate: dynamic analysis runs only against the
# targets listed here. Leave it empty and nothing that touches a target runs.

[workspace]
root = ""

[paths]
ghidra_install = ""
ghidra_mcp_root = ""
frida_root = ""
jdk_home = ""
android_sdk = ""

[ghidra]
project_dir = ""

[mcp]
transport = "stdio"
timeout_s = 180

[frida]
serial = ""

[scope]
authorised = []
"""

#: Defaults are *hints*: `revlab doctor` reports which of them actually exist.
DEFAULT_GHIDRA_CANDIDATES = (
    r"D:\ghidra_12.1.3_PUBLIC",
    r"C:\ghidra_12.1.3_PUBLIC",
    r"C:\ghidra",
)
DEFAULT_MCP_CANDIDATES = (r"D:\ghidra-mcp", r"C:\ghidra-mcp")
DEFAULT_FRIDA_CANDIDATES = (r"D:\frida", r"C:\frida")
ENV_KEYS = {
    "ghidra_install": ("REVLAB_GHIDRA_INSTALL", "GHIDRA_INSTALL_DIR"),
    "ghidra_mcp_root": ("REVLAB_GHIDRA_MCP_ROOT", "GHIDRA_MCP_ROOT"),
    "frida_root": ("REVLAB_FRIDA_ROOT",),
    "jdk_home": ("REVLAB_JAVA_HOME", "GHIDRA_MCP_JAVA_HOME", "JAVA_HOME"),
    "android_sdk": ("REVLAB_ANDROID_SDK", "ANDROID_HOME", "ANDROID_SDK_ROOT"),
}


class ConfigError(RuntimeError):
    """The configuration cannot be used as written."""


class ScopeError(RuntimeError):
    """The target is outside the written-down authorisation scope."""


def _expand(value: str | os.PathLike) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(str(value))))


def _from_env(names: tuple[str, ...]) -> Path | None:
    for name in names:
        value = os.environ.get(name)
        if value and _expand(value).is_dir():
            return _expand(value)
    return None


def _first_existing(candidates: tuple[str, ...]) -> Path | None:
    for raw in candidates:
        if _expand(raw).is_dir():
            return _expand(raw)
    return None


def _resolve(explicit, env_names: tuple[str, ...], candidates: tuple[str, ...]):
    """Explicit config value, then environment, then the first candidate that exists."""
    if explicit:
        return _expand(explicit)
    return _from_env(env_names) or _first_existing(candidates)


def _get(data: dict, *path: str, default=None):
    node = data
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


@dataclass
class Toolchain:
    """Where the external engines live on this machine."""

    ghidra_install: Path | None = None
    ghidra_mcp_root: Path | None = None
    frida_root: Path | None = None
    jdk_home: Path | None = None
    android_sdk: Path | None = None

    # ---- derived locations: each is None when the base path is missing -----
    @property
    def analyze_headless(self) -> Path | None:
        if self.ghidra_install is None:
            return None
        for name in ("analyzeHeadless.bat", "analyzeHeadless"):
            candidate = self.ghidra_install / "support" / name
            if candidate.exists():
                return candidate
        return None

    @property
    def mcp_server_script(self) -> Path | None:
        if self.ghidra_mcp_root is None:
            return None
        for rel in ("server.py", "ghidra_mcp/server.py", "src/server.py"):
            candidate = self.ghidra_mcp_root / rel
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _venv_python(root: Path | None) -> Path | None:
        if root is None:
            return None
        for rel in (".venv/Scripts/python.exe", ".venv/bin/python"):
            candidate = root / rel
            if candidate.exists():
                return candidate
        return None

    @property
    def ghidra_python(self) -> Path | None:
        """Interpreter for the Ghidra MCP server (its PyGhidra venv, if any)."""
        return self._venv_python(self.ghidra_mcp_root)

    @property
    def frida_python(self) -> Path | None:
        return self._venv_python(self.frida_root)

    @property
    def adb(self) -> Path | None:
        for root in (self.android_sdk, self.frida_root):
            if root is not None:
                candidate = root / "platform-tools" / "adb.exe"
                if candidate.exists():
                    return candidate
        which = shutil.which("adb")
        return Path(which) if which else None

    @property
    def frida_server_dir(self) -> Path | None:
        if self.frida_root is None:
            return None
        candidate = self.frida_root / "server"
        return candidate if candidate.is_dir() else None

    def as_dict(self) -> dict[str, str | None]:
        def s(value: Path | None) -> str | None:
            return None if value is None else str(value)

        return {
            "ghidra_install": s(self.ghidra_install),
            "analyze_headless": s(self.analyze_headless),
            "ghidra_mcp_root": s(self.ghidra_mcp_root),
            "ghidra_mcp_server": s(self.mcp_server_script),
            "ghidra_python": s(self.ghidra_python),
            "jdk_home": s(self.jdk_home),
            "frida_root": s(self.frida_root),
            "frida_python": s(self.frida_python),
            "frida_server_dir": s(self.frida_server_dir),
            "adb": s(self.adb),
            "android_sdk": s(self.android_sdk),
        }


@dataclass
class Config:
    """The resolved configuration for one RevLab session."""

    workspace_root: Path = field(default_factory=lambda: Path.cwd() / "workspaces")
    toolchain: Toolchain = field(default_factory=Toolchain)
    authorised: list[str] = field(default_factory=list)
    mcp_transport: str = "stdio"
    mcp_timeout_s: int = 180
    ghidra_project_dir: Path | None = None
    frida_serial: str | None = None
    config_path: Path | None = None
    raw: dict = field(default_factory=dict)

    # ---- authorisation gate ------------------------------------------------
    def is_authorised(self, package_or_path: str) -> bool:
        needle = str(package_or_path).lower()
        return any(
            entry.lower() in needle or needle in entry.lower()
            for entry in self.authorised
        )

    def require_authorised(self, package_or_path: str) -> None:
        """Refuse work on a target the operator has not put on the list."""
        if not self.authorised:
            raise ScopeError(
                "no authorised targets are configured; list them under "
                f"[scope] authorised in {self.config_path or CONFIG_NAME} "
                "(only analyse software you own or are allowed to test)"
            )
        if not self.is_authorised(package_or_path):
            raise ScopeError(
                f"target {package_or_path!r} is not covered by [scope] authorised "
                f"({len(self.authorised)} entry/entries configured)"
            )

    def workspace_for(self, target: str) -> Path:
        """Stable, digest-suffixed workspace directory for one target."""
        stem = Path(str(target)).name or "target"
        keep = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in stem)[:48]
        digest = hashlib.sha256(str(target).encode("utf-8", "replace")).hexdigest()[:8]
        return self.workspace_root / f"{keep}-{digest}"

    def projects_dir(self) -> Path:
        if self.ghidra_project_dir is not None:
            return self.ghidra_project_dir
        return self.workspace_root / "_ghidra_projects"


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Load ``revlab.toml`` (or an explicit file) and resolve the toolchain."""
    config_path = Path(path) if path else None
    if config_path is None:
        candidate = Path.cwd() / CONFIG_NAME
        config_path = candidate if candidate.exists() else None

    data: dict = {}
    if config_path is not None:
        if not config_path.exists():
            raise ConfigError(f"configuration file not found: {config_path}")
        # utf-8-sig: a byte-order mark is a Windows editor artefact ('UTF-8 with
        # BOM' in Notepad, `Set-Content -Encoding utf8` in PowerShell 5.1), not a
        # user error -- refusing it would be pedantry. A real syntax error, on the
        # other hand, must reach the operator as a readable message, not a
        # traceback from deep inside tomllib.
        try:
            data = tomllib.loads(config_path.read_bytes().decode("utf-8-sig"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(
                f"{config_path} is not valid TOML: {exc}\n"
                "  hint: check for a missing '=' or an unquoted Windows path "
                "(use \"C:\\\\dir\" or a literal string 'C:\\dir')"
            ) from exc
        except UnicodeDecodeError as exc:
            raise ConfigError(f"{config_path} is not UTF-8 text: {exc}") from exc

    paths = _get(data, "paths", default={}) or {}
    workspace = _get(data, "workspace", "root")

    return Config(
        workspace_root=(
            _expand(workspace) if workspace else Path.cwd() / "workspaces"
        ),
        toolchain=Toolchain(
            ghidra_install=_resolve(
                paths.get("ghidra_install"), ENV_KEYS["ghidra_install"],
                DEFAULT_GHIDRA_CANDIDATES,
            ),
            ghidra_mcp_root=_resolve(
                paths.get("ghidra_mcp_root"), ENV_KEYS["ghidra_mcp_root"],
                DEFAULT_MCP_CANDIDATES,
            ),
            frida_root=_resolve(
                paths.get("frida_root"), ENV_KEYS["frida_root"],
                DEFAULT_FRIDA_CANDIDATES,
            ),
            jdk_home=_resolve(paths.get("jdk_home"), ENV_KEYS["jdk_home"], ()),
            android_sdk=_resolve(paths.get("android_sdk"), ENV_KEYS["android_sdk"], ()),
        ),
        authorised=[str(item) for item in (_get(data, "scope", "authorised", default=[]) or [])],
        mcp_transport=str(_get(data, "mcp", "transport", default="stdio")),
        mcp_timeout_s=int(_get(data, "mcp", "timeout_s", default=180)),
        ghidra_project_dir=(
            _expand(_get(data, "ghidra", "project_dir"))
            if _get(data, "ghidra", "project_dir")
            else None
        ),
        frida_serial=_get(data, "frida", "serial"),
        config_path=config_path,
        raw=data,
    )


# ---- configuration as something the operator edits -------------------------
def write_default_config(path: str | os.PathLike) -> Path:
    """Write the template to ``path`` (used on first run of the desktop app)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    return target


def _toml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _format_authorised(values: Sequence[str]) -> str:
    """One line for a short list, one entry per line once it stops being short."""
    rendered = [_toml_string(value) for value in values]
    if not rendered:
        return "authorised = []"
    if len(rendered) <= 3 and sum(len(item) for item in rendered) <= 60:
        return "authorised = [" + ", ".join(rendered) + "]"
    return "authorised = [\n" + "".join(f"  {item},\n" for item in rendered) + "]"


def _scope_bounds(lines: list[str]) -> tuple[int, int]:
    """(header index, end index) of the ``[scope]`` table, or ``(-1, -1)``."""
    header = -1
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if stripped == "[scope]":
                header = index
            elif header >= 0:
                return header, index
    if header >= 0:
        return header, len(lines)
    return -1, -1


def set_authorised(
    path: str | os.PathLike, targets: Sequence[str], backup: bool = True
) -> list[str]:
    """Rewrite only ``[scope] authorised``, leaving every other line alone.

    The authorisation list is the one setting an operator changes often, so the
    desktop app edits it in place instead of telling people to open an editor.
    Comments and formatting elsewhere in the file survive because this is a
    text edit, not a re-serialisation: only the value of the ``authorised`` key
    is replaced, and the file is backed up (``revlab.toml.bak``) first. The
    result is parsed before it is written, so a malformed config cannot be
    produced by the UI.
    """
    target = Path(path)
    existed = target.exists()
    text = target.read_bytes().decode("utf-8-sig") if existed else CONFIG_TEMPLATE
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    values = [str(item) for item in targets if str(item).strip()]
    header, end = _scope_bounds(lines)
    if header < 0:
        if lines and lines[-1].strip():
            lines.append("")
        lines += ["[scope]"] + _format_authorised(values).split("\n")
    else:
        key = -1
        for index in range(header + 1, end):
            if re.match(r"^\s*authorised\s*=", lines[index]):
                key = index
                break
        if key < 0:
            block = [""] + _format_authorised(values).split("\n") + [""]
            for offset, item in enumerate(block):
                lines.insert(header + 1 + offset, item)
        else:
            indent = lines[key][: len(lines[key]) - len(lines[key].lstrip())]
            # A value may span lines (`authorised = [` ... `]`); consume it.
            stop, depth = key, 0
            seen_bracket = False
            while stop < len(lines):
                segment = lines[stop].split("=", 1)[1] if stop == key else lines[stop]
                depth += segment.count("[") - segment.count("]")
                seen_bracket = seen_bracket or "[" in segment
                if not seen_bracket or depth <= 0:
                    break
                stop += 1
            block = _format_authorised(values).split("\n")
            block[0] = indent + block[0]
            lines[key : stop + 1] = block

    rendered = newline.join(lines)
    if not rendered.endswith(newline):
        rendered += newline
    tomllib.loads(rendered)  # never write something the loader would reject
    if existed and backup:
        target.with_suffix(target.suffix + ".bak").write_bytes(target.read_bytes())
    target.parent.mkdir(parents=True, exist_ok=True)
    # Bytes, not text: `write_text` would translate "\n" again on Windows and
    # turn the "\r\n" this file already uses into "\r\r\n", which TOML rejects.
    target.write_bytes(rendered.encode("utf-8"))
    tomllib.loads(target.read_bytes().decode("utf-8-sig"))  # what actually landed
    return values
