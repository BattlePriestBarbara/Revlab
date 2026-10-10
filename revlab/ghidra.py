"""Ghidra integration: an MCP client for questions, headless for bulk work.

Two routes, deliberately:

* **MCP** keeps a JVM warm inside the Ghidra MCP server, so asking "decompile
  this function" is cheap enough to do twenty times in a row. That is the route
  an assistant drives.
* **analyzeHeadless** is the batch route: it imports, auto-analyses and runs a
  post-script. Slower to start, but it survives a restart, writes into a project
  store, and needs no long-lived process.

The MCP tools of the server are not contractually fixed, so every high-level
call here resolves a tool name out of a candidate list rather than hard-coding
one name (see :meth:`GhidraMcp.call`).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import Config
from .mcp_client import McpError, McpStdioClient, McpToolResult, client_from_toolchain

SCRIPTS_DIR = Path(__file__).parent / "ghidra_scripts"
SUMMARY_SCRIPT = "ExportProgramSummary.java"


class GhidraError(RuntimeError):
    """Ghidra is missing, misconfigured, or reported an error."""


class GhidraMcp:
    """High-level, question-shaped access to a Ghidra MCP server."""

    #: Candidate tool names per capability; the first match wins. The lists are
    #: ordered from most to least specific because matching falls back to
    #: substring (verified against a real server exposing ``ghidra_*`` tools).
    TOOL_CANDIDATES = {
        "list_functions": ("list_functions", "get_functions", "functions"),
        "decompile": ("decompile_function", "decompile", "get_decompiled_code"),
        "disassemble": ("disassemble_function", "disassemble", "get_assembly"),
        "strings": ("list_strings", "get_strings", "search_strings", "strings"),
        "imports": ("list_imports", "get_imports", "imports"),
        "exports": ("list_exports", "get_exports", "exports", "search_symbols"),
        "xrefs": ("get_xrefs", "xrefs_to", "cross_references", "xrefs", "xref"),
        "call_graph": ("call_graph", "get_call_graph"),
        "byte_search": ("search_bytes", "byte_search", "find_bytes"),
        "import_program": (
            "import_and_analyze", "import_file", "import_program", "open_program", "import",
        ),
        "entry_points": ("list_entry_points", "entry_points"),
        "read_bytes": ("read_bytes", "get_bytes"),
        "data_types": ("list_data_types", "data_types"),
        "memory_blocks": ("list_memory_blocks", "memory_blocks"),
        "status": (
            "session_status", "get_status", "status", "list_programs", "server_status",
        ),
    }

    def __init__(self, config: Config):
        self.config = config
        self.client: McpStdioClient | None = None
        self.resolved: dict[str, str] = {}

    # ---- lifecycle ---------------------------------------------------------
    def open(self, timeout: float | None = None) -> "GhidraMcp":
        if self.client is not None and self.client.alive:
            return self
        self.client = client_from_toolchain(self.config)
        self.client.start()
        try:
            self.client.initialize(timeout=timeout)
            self.client.list_tools(timeout=timeout)
        except McpError as exc:
            self.close()
            raise GhidraError(
                f"Ghidra MCP handshake failed: {exc}. "
                "Check that the server venv has PyGhidra installed and that JAVA_HOME "
                "points at a JDK >= 21."
            ) from exc
        for key, candidates in self.TOOL_CANDIDATES.items():
            found = self.client.find_tool(*candidates)
            if found:
                self.resolved[key] = found
        return self

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    def __enter__(self) -> "GhidraMcp":
        return self.open()

    def __exit__(self, *_exc) -> None:
        self.close()

    # ---- introspection -----------------------------------------------------
    def describe(self) -> dict:
        if self.client is None:
            raise GhidraError("client not started")
        return {
            "command": self.client.command,
            "server_info": self.client.server_info,
            "tool_count": len(self.client.tools),
            "tools": self.client.tool_names(),
            "capabilities_resolved": self.resolved,
            "missing_capabilities": sorted(
                set(self.TOOL_CANDIDATES) - set(self.resolved)
            ),
            "logs": list(self.client.logs)[-20:],
        }

    def call(self, capability: str, arguments: dict | None = None,
             timeout: float | None = None) -> McpToolResult:
        """Call a capability by name; resolves the real tool name once."""
        if self.client is None:
            self.open()
        assert self.client is not None
        tool = self.resolved.get(capability) or self.client.find_tool(
            *self.TOOL_CANDIDATES.get(capability, (capability,))
        )
        if tool is None:
            raise GhidraError(
                f"the Ghidra MCP server exposes no tool for {capability!r}; "
                f"available: {', '.join(self.client.tool_names()[:25])}"
            )
        self.resolved[capability] = tool
        return self.client.call_tool(tool, arguments, timeout=timeout)

    def functions(self, limit: int = 200) -> McpToolResult:
        return self.call("list_functions", {"limit": limit})

    def decompile(self, name: str, timeout: float | None = None) -> McpToolResult:
        return self.call("decompile", {"function_name": name, "name": name}, timeout=timeout)

    def strings(self, query: str = "", limit: int = 200) -> McpToolResult:
        arguments = {"limit": limit}
        if query:
            arguments.update({"query": query, "search": query})
        return self.call("strings", arguments)

    def byte_search(self, pattern: str) -> McpToolResult:
        return self.call("byte_search", {"pattern": pattern, "bytes": pattern})


class GhidraHeadless:
    """Batch route: import, auto-analyse, run the bundled summary post-script."""

    def __init__(self, config: Config, project_dir: Path | None = None):
        self.config = config
        self.project_dir = Path(project_dir or config.projects_dir())

    @property
    def headless(self) -> Path:
        path = self.config.toolchain.analyze_headless
        if path is None:
            raise GhidraError(
                "analyzeHeadless not found; set [paths] ghidra_install in revlab.toml "
                "to the Ghidra installation directory"
            )
        return path

    def _env(self) -> dict:
        env = dict(os.environ)
        jdk = self.config.toolchain.jdk_home
        if jdk is not None:
            env["JAVA_HOME"] = str(jdk)
        env.setdefault("PYTHONUNBUFFERED", "1")
        return env

    def import_and_analyze(self, binary: str | Path, project_name: str | None = None,
                           post_script: str | None = SUMMARY_SCRIPT,
                           script_args: tuple[str, ...] = (),
                           timeout: float = 3600.0, extra: tuple[str, ...] = ()) -> dict:
        """Run one headless import + analysis (+ post-script) and report the outcome."""
        target = Path(binary)
        if not target.exists():
            raise GhidraError(f"target does not exist: {target}")
        self.project_dir.mkdir(parents=True, exist_ok=True)
        project = project_name or target.stem.replace(" ", "_")[:40]

        command = [
            str(self.headless),
            str(self.project_dir),
            project,
            "-import", str(target),
            "-overwrite",
            "-analysisTimeoutPerFile", "900",
        ]
        if post_script:
            command += ["-scriptPath", str(SCRIPTS_DIR), "-postScript", post_script, *script_args]
        command += list(extra)

        completed = subprocess.run(  # noqa: S603 - operator-configured toolchain
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self._env(),
            timeout=timeout,
            check=False,
        )
        return {
            "project_dir": str(self.project_dir),
            "project_name": project,
            "target": str(target),
            "returncode": completed.returncode,
            "command": command,
            "stdout_tail": (completed.stdout or "")[-4000:],
            "stderr_tail": (completed.stderr or "")[-2000:],
            "ok": completed.returncode == 0,
        }

    def summary(self, binary: str | Path, out_file: Path, name_filter: str = "",
                max_functions: int = 40, timeout: float = 3600.0) -> dict:
        """Import a binary and write the JSON summary produced by the post-script."""
        result = self.import_and_analyze(
            binary,
            post_script=SUMMARY_SCRIPT,
            script_args=(str(out_file), name_filter, str(max_functions)),
            timeout=timeout,
        )
        result["summary_file"] = str(out_file)
        result["summary_written"] = Path(out_file).exists()
        return result
