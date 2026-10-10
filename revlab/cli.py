"""RevLab command line interface.

Design rule: the CLI never contains analysis logic. It parses arguments, calls
one function from :mod:`revlab.pipeline` (or a small adapter module), and prints
either human-readable text or ``--json``. That is what lets the web UI and the
MCP server expose exactly the same behaviour.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, ScopeError, load_config
from .doctor import format_doctor, run_doctor
from .evidence import Session
from .pipeline import (
    build_report,
    dynamic_pass,
    elf_triage,
    ghidra_pass,
    list_workspaces,
    open_session,
    session_for,
    static_triage,
)

EXIT_OK, EXIT_USAGE, EXIT_FAILED = 0, 1, 2


def _print(payload, as_json: bool, human: str = "") -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    elif human:
        print(human)
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _add_common(parser: argparse.ArgumentParser) -> None:
    """Let the global flags appear *after* the sub-command as well.

    argparse only reads global options before the command it points at, which
    makes ``revlab triage x.apk --json`` fail with 'unrecognized arguments'.
    Adding the same options to every sub-parser with ``SUPPRESS`` defaults keeps
    both orders working: the value is set only when actually given, so a global
    flag is never clobbered by a sub-parser's default.
    """
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable output")
    parser.add_argument("--config", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    parser.add_argument("--workspace", default=argparse.SUPPRESS, help=argparse.SUPPRESS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revlab",
        description="AI/MCP-driven reverse-engineering workbench (Ghidra + Frida)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "typical flow:\n"
            "  revlab gui                               # desktop window (no CLI needed)\n"
            "  python scripts/make_demo_apk.py          # safe synthetic target\n"
            "  revlab doctor\n"
            "  revlab triage samples/demo.apk\n"
            "  revlab ghidra summary <workspace>/artifacts/native/lib/x86_64/libfoo.so\n"
            "  revlab dynamic run com.example.demo --hook dex_watch --seconds 60\n"
            "  revlab report --target latest\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"revlab {__version__}")
    parser.add_argument("--config", help="path to revlab.toml (default: ./revlab.toml)")
    parser.add_argument("--workspace", help="override the workspace root")
    parser.add_argument("--json", action="store_true", help="machine-readable output")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check the local toolchain and report fixes")
    sub.add_parser("scope", help="show the authorised target list")
    sub.add_parser("sessions", help="list analysis workspaces")

    triage = sub.add_parser("triage", help="static triage of an APK (probe + extract + ELF)")
    triage.add_argument("apk")
    triage.add_argument("--no-extract", action="store_true", help="probe only, extract nothing")
    triage.add_argument("--abi", default="", help="prefer libraries of this ABI, e.g. x86_64")

    elf_cmd = sub.add_parser("elf", help="dependency-free triage of native objects")
    elf_cmd.add_argument("path")
    elf_cmd.add_argument("--target", default="", help="what to record as the authorised target")

    ghidra = sub.add_parser("ghidra", help="Ghidra over MCP, or headless")
    ghidra_sub = ghidra.add_subparsers(dest="ghidra_command", required=True)
    ghidra_sub.add_parser("tools", help="list the tools the MCP server exposes")
    call = ghidra_sub.add_parser("call", help="call one MCP tool directly")
    call.add_argument("tool")
    call.add_argument("--args", default="{}", help="JSON object of tool arguments")
    summary = ghidra_sub.add_parser("summary", help="import + analyse + decompile a binary")
    summary.add_argument("binary")
    summary.add_argument("--target", default="latest", help="session to attach, default 'latest'")
    summary.add_argument("--filter", default="", help="only decompile functions matching this")
    summary.add_argument("--max-functions", type=int, default=40)
    summary.add_argument("--via", choices=("auto", "mcp", "headless"), default="auto")

    dynamic = sub.add_parser("dynamic", help="Frida: device, server, hooks, runs")
    dynamic_sub = dynamic.add_subparsers(dest="dynamic_command", required=True)
    dynamic_sub.add_parser("devices", help="list adb devices")
    dynamic_sub.add_parser("ps", help="list processes visible to Frida")
    dynamic_sub.add_parser("hooks", help="list the hook catalogue")
    server = dynamic_sub.add_parser("server", help="push/start/stop frida-server")
    server.add_argument("action", choices=("start", "stop"))
    server.add_argument("--abi", default="x86_64")
    run = dynamic_sub.add_parser("run", help="run one hook against one target")
    run.add_argument("target", help="package name or pid")
    run.add_argument("--hook", default="api_probe")
    run.add_argument("--seconds", type=float, default=30.0)
    run.add_argument("--mode", choices=("attach", "spawn"), default="attach")
    run.add_argument("--serial", default=None)
    run.add_argument("--target-session", default="latest",
                     help="session to write evidence into, default 'latest'")

    report = sub.add_parser("report", help="render report.md and report.html")
    report.add_argument("--target", default="latest")
    report.add_argument("--no-html", action="store_true")

    mcp = sub.add_parser("mcp", help="expose RevLab itself over MCP")
    mcp_sub = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_sub.add_parser("serve", help="run the RevLab MCP server on stdio")
    mcp_sub.add_parser("tools", help="list the tools RevLab exposes")

    ui = sub.add_parser("ui", help="local web UI (standard library only)")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--no-browser", action="store_true")
    ui.add_argument(
        "--token", default=None,
        help="require ?t=<token> on every request; 'auto' generates one "
             "(mandatory when --host is not loopback)",
    )

    sub.add_parser("gui", help="desktop window (tkinter) over the same passes")

    for subparser in sub.choices.values():
        _add_common(subparser)
    for nested in (ghidra_sub, dynamic_sub, mcp_sub):
        for subparser in nested.choices.values():
            _add_common(subparser)
    return parser


def _human_triage(result: dict) -> str:
    if result.get("error"):
        return f"triage failed: {result['error']}"
    manifest = result.get("manifest", {})
    flags = result.get("flags", {})
    lines = [
        f"target      : {result['target']}",
        f"session     : {result['session']}",
        f"package     : {manifest.get('package', '?')} (v{manifest.get('version_name', '?')})",
        f"application : {manifest.get('application_class') or '<default>'}",
        f"sdk         : min={manifest.get('min_sdk')} target={manifest.get('target_sdk')}",
        f"flags       : encrypted_dex={flags.get('encrypted_dex')} "
        f"abis={','.join(flags.get('abis', [])) or '-'} "
        f"native={flags.get('has_native_libs')} sig_v2={flags.get('v2_signature_block')}",
        f"dex         : {', '.join(d.get('name', '?') for d in result.get('dex', [])) or '-'}",
        f"extracted   : {result.get('extracted', {})}",
    ]
    elf_summary = result.get("elf", {})
    if elf_summary:
        lines.append(
            f"elf         : {elf_summary.get('count')} objects, "
            f"abi={elf_summary.get('by_abi')}"
        )
    severity = result.get("severity", {})
    lines.append(
        "findings    : " + ", ".join(f"{key}={value}" for key, value in severity.items())
    )
    return "\n".join(lines)


def _human_findings(result: dict) -> str:
    findings = result.get("findings", [])
    if not findings:
        return "no findings"
    lines = []
    for item in findings:
        if isinstance(item, dict) and "severity" in item:
            lines.append(f"[{item['severity']:>8}] {item['title']} ({item['confidence']})")
        else:
            lines.append(str(item))
    return "\n".join(lines)


def _human_dynamic(result: dict) -> str:
    if result.get("error"):
        return f"dynamic pass failed: {result['error']}"
    lines = [
        f"hook    : {result['hook']} ({result['mode']})",
        f"target  : {result['target']} pid={result['pid']}",
        f"events  : {result['total']} in {result['seconds']}s -> {result.get('jsonl')}",
        f"by tag  : {result['by_tag']}",
    ]
    if result.get("errors"):
        lines.append(f"errors  : {result['errors']} ({result.get('error_samples')})")
    if result.get("detached"):
        lines.append(f"detached: {result['detached']}")
    if result.get("note"):
        lines.append(f"note    : {result['note']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.workspace:
        config.workspace_root = Path(args.workspace)

    try:
        return _dispatch(args, config)
    except ScopeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FAILED


def _dispatch(args, config: Config) -> int:  # noqa: C901 - a dispatcher is a dispatcher
    command = args.command

    if command == "doctor":
        report = run_doctor(config)
        _print(report, args.json, format_doctor(report))
        return EXIT_OK if report["ok"] else EXIT_FAILED

    if command == "scope":
        payload = {
            "authorised": config.authorised,
            "config_path": str(config.config_path) if config.config_path else None,
            "workspace": str(config.workspace_root),
        }
        _print(payload, args.json, "\n".join(config.authorised) or "(none configured)")
        return EXIT_OK

    if command == "sessions":
        sessions = list_workspaces(config)
        human = "\n".join(
            f"{item['target']}  [{item['kind']}]  findings={item['findings']}  {item['workspace']}"
            for item in sessions
        ) or "(no sessions yet)"
        _print(sessions, args.json, human)
        return EXIT_OK

    if command == "triage":
        result = static_triage(
            config, args.apk, extract=not args.no_extract, abi_preference=args.abi
        )
        _print(result, args.json, _human_triage(result))
        return EXIT_OK if not result.get("error") else EXIT_FAILED

    if command == "elf":
        result = elf_triage(config, args.path, authorised_target=args.target)
        if result.get("error"):
            human = f"elf triage: {result['error']}"
        else:
            human = (
                f"{result['summary']['count']} objects, "
                f"abi={result['summary']['by_abi']}\n" + _human_findings(result)
            )
            if result.get("skipped"):
                for item in result["skipped"][:3]:
                    human += f"\nskipped: {item['path']} -- {item['reason']}"
                if len(result["skipped"]) > 3:
                    human += f"\n... and {len(result['skipped']) - 3} more (see --json)"
        _print(result, args.json, human)
        return EXIT_OK if not result.get("error") else EXIT_FAILED

    if command == "ghidra":
        return _ghidra(args, config)

    if command == "dynamic":
        return _dynamic(args, config)

    if command == "report":
        result = build_report(
            config, target=args.target, html=not args.no_html
        )
        human = "report written:\n" + "\n".join(f"  {path}" for path in result["written"])
        _print(result, args.json, human)
        return EXIT_OK

    if command == "mcp":
        from .mcp_server import describe_tools, serve_stdio

        if args.mcp_command == "tools":
            tools = describe_tools()
            human = "\n".join(f"{tool['name']:28} {tool['description']}" for tool in tools)
            _print({"tools": tools}, args.json, human)
            return EXIT_OK
        return serve_stdio(config)

    if command == "ui":
        from .webui import serve as serve_ui

        token = secrets.token_urlsafe(6) if args.token == "auto" else args.token
        return serve_ui(config, host=args.host, port=args.port,
                        open_browser=not args.no_browser, token=token)

    if command == "gui":
        from .desktop import main as desktop_main

        return desktop_main(config=config)

    print(f"unknown command {command!r}", file=sys.stderr)
    return EXIT_USAGE


def _ghidra(args, config: Config) -> int:
    """Ghidra sub-commands: inspect the MCP surface, call one tool, or summarise."""
    from .ghidra import GhidraMcp

    if args.ghidra_command == "tools":
        with GhidraMcp(config) as mcp:
            description = mcp.describe()
        human = (
            f"server: {description['server_info']}\n"
            f"tools : {description['tool_count']}\n"
            + "\n".join(f"  {name}" for name in description["tools"])
            + f"\nresolved capabilities: {description['capabilities_resolved']}"
        )
        _print(description, args.json, human)
        return EXIT_OK

    if args.ghidra_command == "call":
        try:
            arguments = json.loads(args.args)
        except json.JSONDecodeError as exc:
            print(f"--args must be a JSON object: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if not isinstance(arguments, dict):
            print("--args must be a JSON object", file=sys.stderr)
            return EXIT_USAGE
        with GhidraMcp(config) as mcp:
            result = mcp.client.call_tool(args.tool, arguments)
        payload = result.to_dict()
        _print(payload, args.json, result.text or json.dumps(payload, ensure_ascii=False))
        return EXIT_OK if not result.is_error else EXIT_FAILED

    binary = args.binary
    session = None
    if args.target:
        try:
            session = session_for(config, args.target)
        except FileNotFoundError:
            session = None
    if session is None:
        session = open_session(config, binary, kind="binary")
    result = ghidra_pass(
        config, session, binary, name_filter=args.filter,
        max_functions=args.max_functions, via=args.via,
    )
    _print(result, args.json, json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return EXIT_OK


def _dynamic(args, config: Config) -> int:
    """Frida sub-commands: device/server lifecycle, hook catalogue, hook runs."""
    from .frida_dyn import (
        FridaError,
        adb_devices,
        list_hooks,
        list_processes,
        start_server,
        stop_server,
    )

    command = args.dynamic_command
    if command == "devices":
        devices = adb_devices(config)
        human = "\n".join(f"{item['serial']}  {item['state']}" for item in devices) or "(none)"
        _print(devices, args.json, human)
        return EXIT_OK

    if command == "hooks":
        hooks = list_hooks()
        payload = [
            {"name": hook.name, "summary": hook.summary, "tags": hook.tags, "path": str(hook.path)}
            for hook in hooks
        ]
        human = "\n".join(
            f"{hook.name:20} [{','.join(hook.tags)}] {hook.summary}" for hook in hooks
        ) or "(no hooks)"
        _print(payload, args.json, human)
        return EXIT_OK

    if command == "ps":
        try:
            processes = list_processes(config)
        except FridaError as exc:
            print(f"frida error: {exc}", file=sys.stderr)
            return EXIT_FAILED
        human = "\n".join(f"{item['pid']:>6}  {item['name']}" for item in processes)
        _print(processes, args.json, human)
        return EXIT_OK

    if command == "server":
        try:
            result = (
                start_server(config, abi=args.abi) if args.action == "start"
                else stop_server(config)
            )
        except FridaError as exc:
            print(f"frida error: {exc}", file=sys.stderr)
            return EXIT_FAILED
        _print(result, args.json, json.dumps(result, indent=2, ensure_ascii=False))
        return EXIT_OK

    session = None
    if args.target_session:
        try:
            session = session_for(config, args.target_session)
        except FileNotFoundError:
            session = None
    if session is None:
        session = open_session(config, args.target, kind="dynamic")
    result = dynamic_pass(
        config, session, args.target, args.hook, seconds=args.seconds,
        mode=args.mode, serial=args.serial,
    )
    _print(result, args.json, _human_dynamic(result))
    return EXIT_OK if not result.get("error") else EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())

