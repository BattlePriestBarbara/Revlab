"""A dependency-free MCP client for stdio servers.

RevLab has to talk to a Ghidra MCP server, and the last thing an analysis
toolchain needs is another package that can break. MCP's stdio transport is
simple enough to implement directly: newline-delimited JSON-RPC 2.0 messages
over the server's stdin/stdout, plus a handshake.

Two details that matter in practice:

* servers that print to **stdout** by accident corrupt the protocol, so anything
  that is not valid JSON is treated as log noise and kept in ``logs`` instead of
  raising;
* a request must be able to **time out** (importing and auto-analysing a large
  binary takes minutes), so the stream is drained by a background thread and
  responses are matched by id through a queue.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

PROTOCOL_VERSION = "2024-11-05"


class McpError(RuntimeError):
    """Protocol, transport or tool-level failure."""

    def __init__(self, message: str, code: int | None = None, data=None):
        super().__init__(message)
        self.code = code
        self.data = data


@dataclass
class McpToolResult:
    name: str
    is_error: bool = False
    text: str = ""
    structured: dict | list | None = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.name,
            "is_error": self.is_error,
            "text": self.text,
            "structured": self.structured,
        }


def decode_frames(lines: list[str]) -> list[dict]:
    """Parse whatever the server sent: one JSON per line, or LSP-style framed."""
    messages: list[dict] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line.lower().startswith("content-length:"):
            try:
                length = int(line.split(":", 1)[1].strip())
            except (IndexError, ValueError):
                index += 1
                continue
            index += 1
            body = ""
            while index < len(lines) and len(body.encode("utf-8")) < length:
                body += lines[index]
                index += 1
            try:
                messages.append(json.loads(body))
            except json.JSONDecodeError:
                pass
            continue
        try:
            messages.append(json.loads(line))
        except json.JSONDecodeError:
            messages.append({"__noise__": line})
        index += 1
    return messages


class McpStdioClient:
    """Minimal synchronous MCP client over a child process' stdio."""

    def __init__(self, command: list[str], cwd: str | Path | None = None,
                 env: dict | None = None, timeout: float = 180.0, label: str = "mcp"):
        self.command = [str(part) for part in command]
        self.cwd = str(cwd) if cwd else None
        self.env = env
        self.timeout = float(timeout)
        self.label = label
        self.logs: deque[str] = deque(maxlen=200)
        self._process: subprocess.Popen | None = None
        self._queue: queue.Queue = queue.Queue()
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._next_id = 1
        self._lock = threading.Lock()
        self.server_info: dict = {}
        self.tools: list[dict] = []

    # ---- lifecycle ---------------------------------------------------------
    def start(self) -> "McpStdioClient":
        if self._process is not None:
            return self
        env = dict(os.environ)
        if self.env:
            env.update(self.env)
        env.setdefault("PYTHONUNBUFFERED", "1")
        self._process = subprocess.Popen(  # noqa: S603 - command is operator-configured
            self.command,
            cwd=self.cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(target=self._pump_stderr, daemon=True)
        self._stderr_reader.start()
        return self

    def _pump_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            for message in decode_frames([line]):
                if "__noise__" in message:
                    self.logs.append(str(message["__noise__"])[:400])
                else:
                    self._queue.put(message)

    def _pump_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        for line in process.stderr:
            self.logs.append(line.rstrip()[:400])

    def close(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass
        try:
            process.terminate()
            process.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            try:
                process.kill()
            except OSError:
                pass

    @property
    def alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def __enter__(self) -> "McpStdioClient":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.close()

    # ---- protocol ----------------------------------------------------------
    def _send(self, payload: dict) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise McpError("server is not running (call start() first)")
        try:
            process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise McpError(f"cannot write to {self.label} server: {exc}") from exc

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method: str, params: dict | None = None,
                timeout: float | None = None) -> dict:
        with self._lock:
            request_id = self._next_id
            self._next_id += 1
        self._send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        )
        wait = self.timeout if timeout is None else float(timeout)
        deadline = time.monotonic() + wait
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                hint = f" (last log: {self.logs[-1]!r})" if self.logs else ""
                raise McpError(
                    f"{self.label}: timeout after {wait}s waiting for {method!r}{hint}"
                )
            try:
                message = self._queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                process = self._process
                if process is not None and process.poll() is not None:
                    last = self.logs[-1] if self.logs else "<none>"
                    raise McpError(
                        f"{self.label}: server exited with code {process.returncode}; "
                        f"last log: {last}"
                    )
                continue
            if message.get("id") == request_id:
                if "error" in message:
                    error = message["error"] or {}
                    raise McpError(
                        f"{self.label}: {error.get('message', 'unknown error')}",
                        code=error.get("code"),
                        data=error.get("data"),
                    )
                return message.get("result", {})
            # a notification or an unrelated response: keep reading, lose nothing
            continue

    # ---- convenience -------------------------------------------------------
    def initialize(self, client_name: str = "revlab", timeout: float | None = None) -> dict:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": False}},
                "clientInfo": {"name": client_name, "version": "0.1.0"},
            },
            timeout=timeout,
        )
        self.server_info = result.get("serverInfo", {}) or {}
        self.notify("notifications/initialized")
        return result

    def list_tools(self, timeout: float | None = None) -> list[dict]:
        result = self.request("tools/list", {}, timeout=timeout)
        self.tools = result.get("tools", []) or []
        return self.tools

    def call_tool(self, name: str, arguments: dict | None = None,
                  timeout: float | None = None) -> McpToolResult:
        result = self.request(
            "tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout
        )
        texts: list[str] = []
        structured = None
        for block in result.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(str(block.get("text", "")))
            elif isinstance(block, dict) and "json" in block:
                structured = block["json"]
        if "structuredContent" in result:
            structured = result["structuredContent"]
        return McpToolResult(
            name=name,
            is_error=bool(result.get("isError")),
            text="\n".join(texts),
            structured=structured,
            raw=result,
        )

    def tool_names(self) -> list[str]:
        return [tool.get("name", "") for tool in self.tools]

    def find_tool(self, *candidates: str) -> str | None:
        """Resolve a tool by exact, then case-insensitive, then substring match.

        The Ghidra MCP server is third-party code whose tool names are not
        contractually fixed, so the client adapts instead of hard-coding them.
        """
        available = self.tool_names()
        for candidate in candidates:
            if candidate in available:
                return candidate
        lowered = {name.lower(): name for name in available}
        for candidate in candidates:
            if candidate.lower() in lowered:
                return lowered[candidate.lower()]
        for candidate in candidates:
            for name in available:
                if candidate.lower() in name.lower():
                    return name
        return None


def client_from_toolchain(config, extra_args: list[str] | None = None,
                          label: str = "ghidra-mcp") -> McpStdioClient:
    """Build a client for the configured Ghidra MCP server checkout."""
    toolchain = config.toolchain
    server_script = toolchain.mcp_server_script
    if server_script is None:
        raise McpError(
            "Ghidra MCP server not found; point [paths] ghidra_mcp_root in revlab.toml "
            "at the checkout that contains server.py"
        )
    python = toolchain.ghidra_python or Path("python")
    env: dict[str, str] = {}
    if toolchain.jdk_home is not None:
        env["JAVA_HOME"] = str(toolchain.jdk_home)
    return McpStdioClient(
        [str(python), str(server_script), *(extra_args or [])],
        cwd=server_script.parent,
        env=env,
        timeout=config.mcp_timeout_s,
        label=label,
    )
