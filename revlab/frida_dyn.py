"""Frida dynamic instrumentation, driven from the host.

What this module owns:

* **device and server lifecycle** -- ``adb`` transport, pushing and starting the
  matching ``frida-server``, and reporting the version mismatch that produces
  the misleading "unable to communicate with remote frida-server" error;
* **one hook, one question** -- a catalogue of scripts in ``hooks/``, each
  loaded by name, each streaming ``send()`` payloads back to the host;
* **evidence** -- every message becomes a JSONL record, including failures
  ("hooked, never called"), because those eliminate whole protection classes.

The ``frida`` Python binding is imported lazily: the rest of RevLab keeps
working without it, and the error says exactly what to install.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config

HOOKS_DIR = Path(__file__).parent / "hooks"
_HEADER = re.compile(r"^\s*//\s*(.*)$")


class FridaError(RuntimeError):
    """Frida (or the device it needs) is unavailable or misconfigured."""


def _frida():
    try:
        import frida  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on the local venv
        raise FridaError(
            "the 'frida' Python binding is not importable from this interpreter; "
            "use the Frida venv (see docs/02-environment.md) or run: "
            "python -m pip install -r requirements-frida.txt"
        ) from exc
    return frida


@dataclass
class HookScript:
    name: str
    path: Path
    summary: str = ""
    tags: list[str] = field(default_factory=list)

    def source(self) -> str:
        return self.path.read_text(encoding="utf-8")


def list_hooks(directory: Path | None = None) -> list[HookScript]:
    """Catalogue of available hooks, read from each script's header comments."""
    base = Path(directory or HOOKS_DIR)
    if not base.is_dir():
        return []
    hooks: list[HookScript] = []
    for path in sorted(base.glob("*.js")):
        summary = ""
        tags: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines()[:14]:
            match = _HEADER.match(line)
            if not match:
                continue
            text = match.group(1).strip()
            if text.upper().startswith("@TAGS:"):
                tags = [tag.strip() for tag in text[6:].split(",") if tag.strip()]
            elif text and not summary:
                summary = text
        hooks.append(HookScript(path.stem, path, summary, tags))
    return hooks


def resolve_hook(name_or_path: str) -> HookScript:
    """Accept a hook name (``dex_watch``) or a path to any local .js file."""
    candidate = Path(name_or_path)
    if candidate.suffix == ".js" and candidate.exists():
        return HookScript(candidate.stem, candidate)
    for hook in list_hooks():
        if hook.name == name_or_path:
            return hook
    available = ", ".join(hook.name for hook in list_hooks()) or "<none found>"
    raise FridaError(f"unknown hook {name_or_path!r}; available: {available}")


# ---- device + server -------------------------------------------------------
def adb(config: Config, *args: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    executable = config.toolchain.adb
    if executable is None:
        raise FridaError(
            "adb not found; set [paths] android_sdk (or frida_root containing "
            "platform-tools/) in revlab.toml"
        )
    prefix = ["-s", config.frida_serial] if config.frida_serial else []
    return subprocess.run(  # noqa: S603 - operator-configured toolchain
        [str(executable), *prefix, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def adb_devices(config: Config) -> list[dict]:
    """Parse ``adb devices -l``; one entry per attached transport."""
    result = adb(config, "devices", "-l")
    devices: list[dict] = []
    for line in (result.stdout or "").splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        entry = {"serial": parts[0], "state": parts[1]}
        for token in parts[2:]:
            if ":" in token:
                key, _, value = token.partition(":")
                entry[key] = value
        devices.append(entry)
    return devices


def installed_frida_version(config: Config) -> str:
    """Version of the frida binding inside the *configured* Frida venv."""
    python = config.toolchain.frida_python
    if python is None:
        return ""
    result = subprocess.run(  # noqa: S603
        [str(python), "-c", "import frida; print(frida.__version__)"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def server_binaries(config: Config) -> list[dict]:
    """Extracted frida-server binaries, with the version each is built for."""
    directory = config.toolchain.frida_server_dir
    if directory is None:
        return []
    out: list[dict] = []
    for path in sorted(directory.glob("frida-server*")):
        if path.is_dir() or path.suffix == ".xz":
            continue
        match = re.search(r"frida-server-([0-9][\w.]*?)-android-([\w-]+)", path.name)
        out.append(
            {
                "path": str(path),
                "name": path.name,
                "version": match.group(1) if match else "",
                "arch": match.group(2) if match else "",
            }
        )
    return out


def pick_server(config: Config, abi: str = "x86_64") -> dict:
    binaries = [entry for entry in server_binaries(config) if abi in entry["arch"]]
    if not binaries:
        available = ", ".join(entry["name"] for entry in server_binaries(config)) or "<none>"
        raise FridaError(
            f"no frida-server binary for {abi!r} under "
            f"{config.toolchain.frida_server_dir}; available: {available}. "
            "frida-server ships as .xz, so unpack it first"
        )
    return binaries[-1]


def start_server(config: Config, abi: str = "x86_64",
                 remote: str = "/data/local/tmp/frida-server") -> dict:
    """Push, chmod and start frida-server on the selected device."""
    binary = pick_server(config, abi)
    cli_version = installed_frida_version(config)
    if cli_version and binary["version"] and cli_version != binary["version"]:
        raise FridaError(
            f"frida binding {cli_version} does not match frida-server "
            f"{binary['version']} ({binary['name']}); that mismatch shows up as "
            "'unable to communicate with remote frida-server'"
        )
    pushed = adb(config, "push", binary["path"], remote)
    if pushed.returncode != 0:
        raise FridaError(f"adb push failed: {(pushed.stderr or pushed.stdout).strip()}")
    adb(config, "shell", f"su -c 'chmod 755 {remote}'")
    started = adb(config, "shell", f"su -c '{remote} &'", timeout=30.0)
    return {
        "binary": binary,
        "remote": remote,
        "cli_version": cli_version,
        "push_stdout": (pushed.stdout or "").strip(),
        "start_stdout": (started.stdout or "").strip(),
        "start_stderr": (started.stderr or "").strip(),
    }


def stop_server(config: Config, remote: str = "/data/local/tmp/frida-server") -> dict:
    result = adb(config, "shell", f"su -c 'pkill -f {remote}'")
    return {"returncode": result.returncode, "output": (result.stdout or result.stderr).strip()}


# ---- hook execution --------------------------------------------------------
class EventSink:
    """Collects ``send()`` payloads from a hook and mirrors them into JSONL."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict] = []
        self.by_tag: dict[str, int] = {}
        self.errors: list[str] = []

    def __call__(self, message: dict, data=None) -> None:
        kind = message.get("type", "send")
        payload = message.get("payload", message)
        if kind == "error":
            entry = {
                "kind": "script-error",
                "description": message.get("description", ""),
                "stack": (message.get("stack") or "")[:1500],
            }
            self.errors.append(entry["description"] or "script error")
        else:
            entry = {"kind": kind, "payload": payload}
            tag = ""
            if isinstance(payload, dict):
                tag = str(payload.get("tag") or payload.get("type") or "")
            if tag:
                self.by_tag[tag] = self.by_tag.get(tag, 0) + 1
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.records.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    @property
    def stats(self) -> dict:
        return {
            "total": len(self.records),
            "by_tag": dict(sorted(self.by_tag.items(), key=lambda kv: -kv[1])),
            "errors": len(self.errors),
            "error_samples": self.errors[:5],
        }


def select_device(config: Config, serial: str | None = None):
    frida = _frida()
    serial = serial or config.frida_serial
    try:
        return frida.get_device(serial, timeout=10) if serial else frida.get_usb_device(timeout=10)
    except Exception as exc:  # frida raises its own error hierarchy
        raise FridaError(
            f"cannot select a Frida device ({serial or 'usb'}): {exc}. "
            "Check `revlab doctor` and that frida-server runs on the device."
        ) from exc


def list_processes(config: Config, serial: str | None = None, limit: int = 60) -> list[dict]:
    device = select_device(config, serial)
    processes = sorted(
        ({"pid": proc.pid, "name": proc.name} for proc in device.enumerate_processes()),
        key=lambda item: item["name"].lower(),
    )
    return processes[:limit]


def run_hook(config: Config, target: str, hook_name: str, seconds: float = 30.0,
             mode: str = "attach", serial: str | None = None,
             output: Path | None = None, script_args: dict | None = None) -> dict:
    """Load one hook against one target and collect everything it reports.

    ``mode='attach'`` (default) hooks a running process; ``mode='spawn'`` starts
    the app under instrumentation. Attach is the default on purpose: a spawn
    workflow against a process that kills itself early loses the session.
    """
    if mode not in ("attach", "spawn"):
        raise FridaError(f"mode must be 'attach' or 'spawn', got {mode!r}")
    if seconds <= 0:
        raise FridaError("seconds must be positive")

    hook = resolve_hook(hook_name)
    frida = _frida()
    device = select_device(config, serial)
    sink = EventSink(output)
    session = None
    script = None
    pid = None
    detached: dict = {}

    def on_detached(reason, crash=None):
        detached["reason"] = str(reason)
        if crash is not None:
            detached["crash"] = str(crash)

    try:
        if mode == "spawn":
            pid = device.spawn([target])
            session = device.attach(pid)
        else:
            session = device.attach(int(target) if str(target).isdigit() else target)
        session.on("detached", on_detached)

        source = hook.source()
        preamble = ""
        if script_args:
            preamble = "const REVLAB_ARGS = " + json.dumps(script_args) + ";\n"
        script = session.create_script(preamble + source, name=f"revlab:{hook.name}")
        script.on("message", sink)
        script.load()

        if mode == "spawn" and pid is not None:
            device.resume(pid)

        deadline = time.monotonic() + float(seconds)
        while time.monotonic() < deadline:
            if detached:
                break
            time.sleep(0.25)
        try:
            script.unload()
        except Exception:  # noqa: BLE001 - unloading a dead script is expected
            pass
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:  # noqa: BLE001 - already gone
                pass

    stats = sink.stats
    if stats["total"] == 0 and not detached:
        stats["note"] = (
            "hook loaded but never reported anything: the API it watches may not be "
            "reachable on this device/architecture"
        )
    return {
        "hook": hook.name,
        "hook_path": str(hook.path),
        "target": target,
        "mode": mode,
        "pid": pid,
        "seconds": seconds,
        "jsonl": str(output) if output else None,
        "detached": detached,
        **stats,
    }
