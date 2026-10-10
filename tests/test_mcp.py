"""MCP on both sides: RevLab as a server, and RevLab as a client.

The client tests start a real child process that speaks the protocol, because
the interesting MCP failures are transport failures (framing, timeouts, a server
that prints noise on stdout) and those cannot be tested with a mock object.
"""

from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from revlab import mcp_server
from revlab.config import Config
from revlab.mcp_client import McpError, McpStdioClient, decode_frames

MOCK_SERVER = '''
import json, sys, time

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = message.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05",
                  "serverInfo": {"name": "mock-ghidra", "version": "9.9"},
                  "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": [{"name": "decompile_function", "description": "decompile"},
                            {"name": "list_functions", "description": "functions"}]}
    elif method == "tools/call":
        print("warning: noisy log line")   # stdout noise on purpose
        sys.stdout.flush()
        params = message.get("params") or {}
        if params.get("name") == "explode":
            result = {"content": [{"type": "text", "text": "boom"}], "isError": True}
        elif params.get("name") == "slow":
            time.sleep(5)
            result = {"content": [{"type": "text", "text": "late"}]}
        else:
            result = {"content": [{"type": "text", "text": "ok:" + str(params.get("arguments"))}],
                      "structuredContent": {"tool": params.get("name")}}
    else:
        result = {}
    if message.get("id") is not None:
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}))
        sys.stdout.flush()
'''


class FrameDecodingTests(unittest.TestCase):
    def test_newline_delimited_json(self) -> None:
        frames = decode_frames(['{"jsonrpc": "2.0", "id": 1, "result": {}}', ""])
        self.assertEqual(frames[0]["id"], 1)

    def test_noise_is_captured_not_raised(self) -> None:
        frames = decode_frames(["starting up", '{"id": 2}'])
        self.assertIn("__noise__", frames[0])
        self.assertEqual(frames[1]["id"], 2)

    def test_content_length_framing(self) -> None:
        body = '{"jsonrpc":"2.0","id":3,"result":{"ok":true}}'
        frames = decode_frames(["Content-Length: %d" % len(body), body])
        self.assertEqual(frames[0]["result"]["ok"], True)


class ServerSideTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Config(workspace_root=Path(self.tmp.name) / "ws",
                             authorised=["demo.apk"])

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_initialize_handshake(self) -> None:
        response = mcp_server.handle_message(
            self.config, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        self.assertEqual(response["result"]["serverInfo"]["name"], "revlab")
        self.assertIn("tools", response["result"]["capabilities"])

    def test_notification_is_silent(self) -> None:
        self.assertIsNone(
            mcp_server.handle_message(
                self.config, {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
        )

    def test_tools_list_has_schemas(self) -> None:
        response = mcp_server.handle_message(
            self.config, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        )
        tools = response["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertIn("revlab_triage_apk", names)
        self.assertIn("revlab_frida_run", names)
        for tool in tools:
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertTrue(tool["description"])

    def test_unknown_method_returns_jsonrpc_error(self) -> None:
        response = mcp_server.handle_message(
            self.config, {"jsonrpc": "2.0", "id": 3, "method": "does/not/exist"}
        )
        self.assertEqual(response["error"]["code"], -32601)

    def test_unknown_tool_is_an_error_result_not_a_crash(self) -> None:
        is_error, text = mcp_server.call_tool(self.config, "revlab_nope", {})
        self.assertTrue(is_error)
        self.assertIn("unknown tool", text)

    def test_scope_tool_reports_the_gate(self) -> None:
        is_error, text = mcp_server.call_tool(self.config, "revlab_scope", {})
        self.assertFalse(is_error)
        self.assertIn("demo.apk", text)

    def test_missing_argument_is_reported_as_error(self) -> None:
        is_error, text = mcp_server.call_tool(self.config, "revlab_triage_apk", {})
        self.assertTrue(is_error)
        self.assertIn("apk", text)

    def test_tool_call_round_trip(self) -> None:
        response = mcp_server.handle_message(
            self.config,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "revlab_scope", "arguments": {}},
            },
        )
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(response["result"]["content"][0]["type"], "text")


class ClientTests(unittest.TestCase):
    """These run the mock server as a real subprocess."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.server_path = Path(self.tmp.name) / "mock_server.py"
        self.server_path.write_text(textwrap.dedent(MOCK_SERVER), encoding="utf-8")
        self.client = McpStdioClient(
            [sys.executable, str(self.server_path)], timeout=10.0, label="mock"
        )
        self.client.start()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.client.close)

    def test_handshake_and_tool_discovery(self) -> None:
        self.client.initialize()
        self.client.list_tools()
        self.assertEqual(self.client.server_info["name"], "mock-ghidra")
        self.assertEqual(self.client.tool_names(), ["decompile_function", "list_functions"])

    def test_call_tool_returns_text_and_structured_content(self) -> None:
        self.client.initialize()
        self.client.list_tools()
        result = self.client.call_tool("decompile_function", {"function_name": "main"})
        self.assertFalse(result.is_error)
        self.assertIn("ok:", result.text)
        self.assertEqual(result.structured["tool"], "decompile_function")

    def test_tool_level_error_is_flagged_not_raised(self) -> None:
        self.client.initialize()
        result = self.client.call_tool("explode", {})
        self.assertTrue(result.is_error)

    def test_noisy_stdout_is_kept_as_logs(self) -> None:
        self.client.initialize()
        self.client.list_tools()
        self.client.call_tool("list_functions", {})
        self.assertTrue(any("noisy log line" in line for line in self.client.logs))

    def test_timeout_is_reported_with_context(self) -> None:
        self.client.initialize()
        with self.assertRaises(McpError) as ctx:
            self.client.call_tool("slow", {}, timeout=1.0)
        self.assertIn("timeout", str(ctx.exception))

    def test_find_tool_matches_by_substring(self) -> None:
        self.client.initialize()
        self.client.list_tools()
        self.assertEqual(self.client.find_tool("decompile"), "decompile_function")
        self.assertEqual(self.client.find_tool("nope", "list_functions"), "list_functions")
        self.assertIsNone(self.client.find_tool("nonexistent"))

    def test_write_after_close_is_reported(self) -> None:
        self.client.close()
        with self.assertRaises(McpError):
            self.client.request("tools/list")


if __name__ == "__main__":
    unittest.main()
