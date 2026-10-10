"""RevLab as an MCP server: the whole workbench, exposed as tools.

This is the mirror image of :mod:`revlab.mcp_client`. There, RevLab *uses* a
Ghidra MCP server; here, RevLab *is* one, so an assistant (Cline, Claude
Desktop, anything speaking MCP) can run triage, ask Ghidra questions, drive
Frida and write reports without a human relaying JSON.

Implemented directly over stdio with the standard library: newline-delimited
JSON-RPC 2.0, methods ``initialize`` / ``tools/list`` / ``tools/call`` /
``ping``, notifications acknowledged by silence.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

from . import __version__
from .config import Config, ScopeError
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

PROTOCOL_VERSION = "2024-11-05"
MAX_TEXT = 200_000


def _tool(name: str, description: str, properties: dict | None = None,
          required: tuple[str, ...] = ()) -> dict:
    schema: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = list(required)
    return {"name": name, "description": description, "inputSchema": schema}


def describe_tools() -> list[dict]:
    """The tool surface RevLab offers to an assistant."""
    return [
        _tool("revlab_doctor", "检查本机工具链（Ghidra / JDK / Frida / adb）并给出修复建议"),
        _tool("revlab_scope", "列出当前授权分析范围与被拒绝的规则"),
        _tool("revlab_sessions", "列出所有分析工作区及其发现统计"),
        _tool(
            "revlab_triage_apk",
            "对一个 APK 做静态三连：清单解析、ZIP/DEX 熵分析、原生库 ELF triage",
            {
                "apk": {"type": "string", "description": "APK 路径"},
                "extract": {"type": "boolean", "default": True},
                "abi": {"type": "string", "description": "优先关注的 ABI，例如 x86_64"},
            },
            ("apk",),
        ),
        _tool(
            "revlab_elf_triage",
            "对目录或单个文件做无依赖 ELF triage（ABI/SONAME/NEEDED/导出/JNI 入口/横幅）",
            {"path": {"type": "string"}},
            ("path",),
        ),
        _tool("revlab_ghidra_tools", "列出 Ghidra MCP 服务器暴露的工具与能力解析结果"),
        _tool(
            "revlab_ghidra_call",
            "直接调用 Ghidra MCP 服务器的某个工具（用于反编译、交叉引用、字符串搜索等）",
            {"tool": {"type": "string"}, "arguments": {"type": "object"}},
            ("tool",),
        ),
        _tool(
            "revlab_ghidra_summary",
            "用 analyzeHeadless 导入并分析一个二进制，反编译高引用函数并写入证据",
            {
                "binary": {"type": "string"},
                "target": {"type": "string", "description": "写入哪个会话，默认 latest"},
                "filter": {"type": "string", "description": "只反编译名字包含该串的函数"},
                "max_functions": {"type": "integer", "default": 40},
                "via": {"type": "string", "enum": ["auto", "mcp", "headless"], "default": "auto"},
            },
            ("binary",),
        ),
        _tool("revlab_frida_devices", "列出 adb 设备"),
        _tool("revlab_frida_hooks", "列出内置 hook 目录（一问一脚本）"),
        _tool(
            "revlab_frida_run",
            "对目标进程执行一个 hook 并把事件写入证据（attach 为默认模式）",
            {
                "target": {"type": "string", "description": "包名或 pid"},
                "hook": {"type": "string", "default": "api_probe"},
                "seconds": {"type": "number", "default": 30},
                "mode": {"type": "string", "enum": ["attach", "spawn"], "default": "attach"},
                "session": {"type": "string", "default": "latest"},
            },
            ("target",),
        ),
        _tool(
            "revlab_findings",
            "读取某个会话的发现列表（按严重性排序）",
            {"target": {"type": "string", "default": "latest"}},
        ),
        _tool(
            "revlab_report",
            "把会话证据渲染成 report.md / report.html",
            {"target": {"type": "string", "default": "latest"},
             "html": {"type": "boolean", "default": True}},
        ),
    ]


def _session(config: Config, spec: str):
    if spec and spec != "latest":
        try:
            return session_for(config, spec)
        except FileNotFoundError:
            return open_session(config, spec, kind="manual")
    return session_for(config, "latest")


def _h_doctor(config: Config, args: dict) -> dict:
    from .doctor import run_doctor

    return run_doctor(config)


def _h_scope(config: Config, args: dict) -> dict:
    return {
        "authorised": config.authorised,
        "config_path": str(config.config_path) if config.config_path else None,
        "workspace": str(config.workspace_root),
        "rule": "targets must match an entry in [scope] authorised (case-insensitive substring)",
    }


def _h_sessions(config: Config, args: dict) -> dict:
    return {"sessions": list_workspaces(config)}


def _h_triage(config: Config, args: dict) -> dict:
    return static_triage(
        config,
        args["apk"],
        extract=bool(args.get("extract", True)),
        abi_preference=str(args.get("abi", "")),
    )


def _h_elf(config: Config, args: dict) -> dict:
    return elf_triage(config, args["path"])


def _h_ghidra_tools(config: Config, args: dict) -> dict:
    from .ghidra import GhidraMcp

    with GhidraMcp(config) as mcp:
        return mcp.describe()


def _h_ghidra_call(config: Config, args: dict) -> dict:
    from .ghidra import GhidraMcp

    arguments = args.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise ValueError("'arguments' must be an object")
    with GhidraMcp(config) as mcp:
        mcp.open()
        result = mcp.client.call_tool(args["tool"], arguments)
    return result.to_dict()


def _h_ghidra_summary(config: Config, args: dict) -> dict:
    session = _session(config, str(args.get("target", "latest")))
    return ghidra_pass(
        config,
        session,
        args["binary"],
        name_filter=str(args.get("filter", "")),
        max_functions=int(args.get("max_functions", 40)),
        via=str(args.get("via", "auto")),
    )


def _h_frida_devices(config: Config, args: dict) -> dict:
    from .frida_dyn import adb_devices

    return {"devices": adb_devices(config)}


def _h_frida_hooks(config: Config, args: dict) -> dict:
    from .frida_dyn import list_hooks

    return {
        "hooks": [
            {"name": hook.name, "summary": hook.summary, "tags": hook.tags}
            for hook in list_hooks()
        ]
    }


def _h_frida_run(config: Config, args: dict) -> dict:
    target = str(args["target"])
    session = _session(config, str(args.get("session", "latest")))
    if str(session.target) != target:
        session = open_session(config, target, kind="dynamic")
    return dynamic_pass(
        config,
        session,
        target,
        str(args.get("hook", "api_probe")),
        seconds=float(args.get("seconds", 30)),
        mode=str(args.get("mode", "attach")),
    )


def _h_findings(config: Config, args: dict) -> dict:
    from .report import SEVERITY_ORDER, _sorted_findings

    session = _session(config, str(args.get("target", "latest")))
    return {
        "target": session.target,
        "workspace": str(session.root),
        "severity_order": list(SEVERITY_ORDER),
        "findings": _sorted_findings(session),
    }


def _h_report(config: Config, args: dict) -> dict:
    session = _session(config, str(args.get("target", "latest")))
    return build_report(config, session, html=bool(args.get("html", True)))


HANDLERS: dict[str, Callable[[Config, dict], dict]] = {
    "revlab_doctor": _h_doctor,
    "revlab_scope": _h_scope,
    "revlab_sessions": _h_sessions,
    "revlab_triage_apk": _h_triage,
    "revlab_elf_triage": _h_elf,
    "revlab_ghidra_tools": _h_ghidra_tools,
    "revlab_ghidra_call": _h_ghidra_call,
    "revlab_ghidra_summary": _h_ghidra_summary,
    "revlab_frida_devices": _h_frida_devices,
    "revlab_frida_hooks": _h_frida_hooks,
    "revlab_frida_run": _h_frida_run,
    "revlab_findings": _h_findings,
    "revlab_report": _h_report,
}


def call_tool(config: Config, name: str, arguments: dict) -> tuple[bool, str]:
    """Run one tool; return (is_error, text). Never raises past this boundary."""
    handler = HANDLERS.get(name)
    if handler is None:
        return True, f"unknown tool {name!r}; known: {', '.join(sorted(HANDLERS))}"
    try:
        payload = handler(config, arguments or {})
    except ScopeError as exc:
        return True, f"refused by the authorisation gate: {exc}"
    except Exception as exc:  # noqa: BLE001 - a tool failure must not kill the server
        return True, f"{type(exc).__name__}: {exc}"
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + f"\n... truncated ({len(text)} chars total)"
    return False, text


def handle_message(config: Config, message: dict) -> dict | None:
    """Dispatch one JSON-RPC message; None means 'notification, stay silent'."""
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "revlab", "version": __version__},
                "instructions": (
                    "RevLab 逆向工程工作台：先 revlab_doctor 确认环境，再 revlab_triage_apk "
                    "做静态三连。动态能力只对授权范围内的目标生效。"
                ),
            },
        }
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": describe_tools()}}
    if method == "tools/call":
        params = message.get("params") or {}
        is_error, text = call_tool(config, params.get("name", ""), params.get("arguments") or {})
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": is_error},
        }
    if request_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def serve_stdio(config: Config) -> int:
    """Run the server until stdin closes: the transport MCP clients expect."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        response = handle_message(config, message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0
