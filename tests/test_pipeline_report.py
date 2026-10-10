"""End-to-end: static triage -> evidence -> report, plus hook catalogue integrity.

This is the test that proves the design works without Ghidra, Frida or a device:
a synthetic APK goes in, a session with records, findings, artifacts and a
regenerated report comes out.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from revlab import cli, frida_dyn, pipeline, report
from revlab.config import Config
from revlab.evidence import Finding, Session
from revlab.mcp_client import McpStdioClient

from . import fixtures


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "target-abc"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_records_and_findings_are_append_only(self) -> None:
        session = Session.open(self.root, "demo.apk", kind="apk")
        self.assertTrue((self.root / "session.json").exists())
        session.record("static", "apk-probe", {"note": "first"})
        session.record("static", "apk-probe", {"note": "second"})
        session.find(Finding(id="x", title="标题", severity="high", confidence=0.9))
        session.save_artifact("blob.json", '{"ok": true}')

        self.assertEqual(len(session.records), 2)
        self.assertEqual(len(session.findings), 1)
        summary = session.summary()
        self.assertEqual(summary["records"], 2)
        self.assertEqual(summary["severity"]["high"], 1)
        self.assertEqual(summary["stages"], ["static"])
        self.assertEqual(summary["artifacts"], 1)

    def test_reopen_counts_and_keeps_evidence(self) -> None:
        first = Session.open(self.root, "demo.apk")
        first.record("static", "kind", {})
        second = Session.open(self.root, "demo.apk")
        self.assertEqual(len(second.records), 1)
        self.assertEqual(second.meta["reopen_count"], 1)

    def test_confidence_and_severity_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            Finding(id="x", title="t", confidence=1.5)
        with self.assertRaises(ValueError):
            Finding(id="x", title="t", severity="catastrophic")

    def test_corrupt_line_is_marked_not_fatal(self) -> None:
        session = Session.open(self.root, "demo.apk")
        session.record("static", "kind", {})
        with (self.root / "records.jsonl").open("a", encoding="utf-8") as handle:
            handle.write("{not json\n")
        records = session.records
        self.assertEqual(len(records), 2)
        self.assertEqual(records[-1]["kind"], "unparsable-line")


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.apk = fixtures.build_manifest_apk(self.root / "demo.apk")
        self.config = Config(
            workspace_root=self.root / "ws",
            authorised=["demo.apk", "com.example.demo"],
            ghidra_project_dir=self.root / "ws" / "_projects",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_static_triage_end_to_end(self) -> None:
        result = pipeline.static_triage(self.config, self.apk)
        session_root = Path(result["session"])
        self.assertTrue((session_root / "session.json").exists())
        self.assertTrue((session_root / "records.jsonl").exists())
        self.assertTrue((session_root / "findings.jsonl").exists())
        self.assertTrue((session_root / "artifacts" / "apk-probe.json").exists())
        self.assertTrue((session_root / "artifacts" / "elf-triage.json").exists())

        self.assertEqual(len(list((session_root / "artifacts" / "native").rglob("*.so"))), 2)
        self.assertEqual(
            len(list((session_root / "artifacts" / "dex").glob("*.dex"))), 2
        )
        self.assertEqual(result["manifest"]["package"], "com.example.demo")
        self.assertEqual(result["extracted"], {"native": 2, "dex": 2})
        self.assertEqual(result["elf"]["count"], 2)
        self.assertGreaterEqual(result["findings"], 8)

        session = pipeline.session_for(self.config, str(session_root))
        kinds = {record["kind"] for record in session.records}
        self.assertEqual(kinds, {"apk-probe", "extracted", "elf-triage"})
        self.assertEqual(session.summary()["stages"], ["static"])

    def test_scope_gate_blocks_triage(self) -> None:
        from revlab.config import ScopeError

        with self.assertRaises(ScopeError):
            pipeline.static_triage(self.config, self.root / "other.apk")

    def test_elf_triage_standalone(self) -> None:
        libdir = self.root / "libs"
        fixtures.build_elf(libdir / "liba.so", exports=("JNI_OnLoad",))
        config = Config(workspace_root=self.root / "ws2", authorised=["libs"])
        result = pipeline.elf_triage(config, libdir)
        self.assertEqual(result["summary"]["count"], 1)
        self.assertIn(
            "register-natives-only", {finding["id"] for finding in result["findings"]}
        )

    def test_report_renders_findings_and_next_steps(self) -> None:
        pipeline.static_triage(self.config, self.apk)
        session = pipeline.session_for(self.config, "latest")
        markdown = report.render_markdown(session)
        self.assertIn("RevLab 分析报告", markdown)
        self.assertIn("## 2. 发现明细", markdown)
        self.assertIn("DEX 主体不是明文代码", markdown)
        self.assertIn("## 5. 下一步建议", markdown)
        self.assertIn("dex_watch", markdown)  # the concrete follow-up for the packer tag

        html = report.render_html(session)
        self.assertIn("<!doctype html>", html)
        self.assertIn('class="finding critical"', html)

        written = report.write_report(session)
        self.assertEqual({path.name for path in written}, {"report.md", "report.html"})
        for path in written:
            self.assertTrue(path.read_text(encoding="utf-8").strip())

    def test_findings_are_json_serialisable_as_emitted(self) -> None:
        pipeline.static_triage(self.config, self.apk)
        session = pipeline.session_for(self.config, "latest")
        for finding in session.findings:
            json.dumps(finding)

    def test_build_report_through_pipeline(self) -> None:
        pipeline.static_triage(self.config, self.apk)
        result = pipeline.build_report(self.config, target="latest")
        self.assertEqual(len(result["written"]), 2)
        for path in result["written"]:
            self.assertTrue(Path(path).is_file())

    def test_list_workspaces_summarises_sessions(self) -> None:
        pipeline.static_triage(self.config, self.apk)
        workspaces = pipeline.list_workspaces(self.config)
        self.assertEqual(len(workspaces), 1)
        self.assertEqual(workspaces[0]["kind"], "apk")
        self.assertGreater(workspaces[0]["findings"], 0)

    def test_rerunning_a_pass_does_not_double_count_findings(self) -> None:
        pipeline.static_triage(self.config, self.apk)
        session = pipeline.session_for(self.config, "latest")
        unique_first = len(session.unique_findings)
        entries_first = len(session.findings)
        self.assertGreater(entries_first, 0)

        pipeline.static_triage(self.config, self.apk)  # same target, same session
        session = pipeline.session_for(self.config, "latest")
        self.assertGreater(len(session.findings), entries_first)   # the log grew
        self.assertEqual(len(session.unique_findings), unique_first)  # the report did not
        summary = session.summary()
        self.assertEqual(summary["finding_entries"], len(session.findings))
        self.assertEqual(summary["findings"], unique_first)

    def test_dynamic_pass_reports_missing_boundary_instead_of_crashing(self) -> None:
        pipeline.static_triage(self.config, self.apk)
        session = pipeline.session_for(self.config, "latest")
        # no frida binding / no device here: the pass must record why and stop
        result = pipeline.dynamic_pass(
            self.config, session, "com.example.demo", "api_probe", seconds=1
        )
        if "error" in result:
            self.assertIn("hook", result)
            self.assertIn(
                "frida-unavailable",
                {record["kind"] for record in session.records},
            )


class HookCatalogueTests(unittest.TestCase):
    def test_hooks_are_discovered_with_summaries_and_tags(self) -> None:
        hooks = frida_dyn.list_hooks()
        self.assertEqual(
            {hook.name for hook in hooks},
            {"api_probe", "anti_debug_probe", "jni_boundary", "dex_watch"},
        )
        for hook in hooks:
            self.assertTrue(hook.summary, hook.name)
            self.assertTrue(hook.tags, hook.name)
            self.assertIn("send(", hook.source())

    def test_resolve_hook_by_name_and_reject_unknown(self) -> None:
        self.assertEqual(frida_dyn.resolve_hook("dex_watch").name, "dex_watch")
        with self.assertRaises(frida_dyn.FridaError):
            frida_dyn.resolve_hook("does_not_exist")

    def test_server_binaries_parse_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server_dir = Path(tmp) / "server"
            server_dir.mkdir()
            (server_dir / "frida-server-17.18.0-android-x86_64").write_bytes(b"")
            (server_dir / "frida-server-17.18.0-android-arm64").write_bytes(b"")
            (server_dir / "frida-server-17.18.0-android-x86_64.xz").write_bytes(b"")
            config = Config()
            config.toolchain.frida_root = Path(tmp)
            binaries = frida_dyn.server_binaries(config)
            self.assertEqual(len(binaries), 2)  # the .xz is not a runnable binary
            self.assertEqual(binaries[0]["version"], "17.18.0")
            self.assertIn("x86_64", frida_dyn.pick_server(config, "x86_64")["arch"])

    def test_missing_server_binary_says_what_to_do(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "server").mkdir()
            config = Config()
            config.toolchain.frida_root = Path(tmp)
            with self.assertRaises(frida_dyn.FridaError) as ctx:
                frida_dyn.pick_server(config, "x86_64")
            self.assertIn("no frida-server binary", str(ctx.exception))


class CliParserTests(unittest.TestCase):
    """Flag placement: the global options must work before *and* after a command."""

    def test_global_json_before_and_after_subcommand(self) -> None:
        parser = cli.build_parser()
        before = parser.parse_args(["--json", "doctor"])
        after = parser.parse_args(["triage", "x.apk", "--json", "--no-extract"])
        self.assertTrue(before.json)
        self.assertTrue(after.json)
        self.assertTrue(after.no_extract)
        self.assertEqual(after.apk, "x.apk")

    def test_json_defaults_to_false(self) -> None:
        args = cli.build_parser().parse_args(["sessions"])
        self.assertFalse(args.json)

    def test_config_and_workspace_accepted_after_command(self) -> None:
        args = cli.build_parser().parse_args(
            ["sessions", "--config", "c.toml", "--workspace", "w"]
        )
        self.assertEqual(args.config, "c.toml")
        self.assertEqual(args.workspace, "w")

    def test_nested_subcommands_accept_the_flag(self) -> None:
        args = cli.build_parser().parse_args(
            ["ghidra", "tools", "--json"]
        )
        self.assertTrue(args.json)
        args = cli.build_parser().parse_args(
            ["dynamic", "run", "com.example.demo", "--hook", "dex_watch", "--json"]
        )
        self.assertTrue(args.json)
        self.assertEqual(args.hook, "dex_watch")


class CliDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = self.root / "revlab.toml"
        self.config_path.write_text(
            f"""
[workspace]
root = "{(self.root / 'ws').as_posix()}"

[scope]
authorised = ["demo.apk"]
""",
            encoding="utf-8",
        )
        self.apk = fixtures.build_manifest_apk(self.root / "demo.apk")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, argv: list[str]) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(argv)
        return code, buffer.getvalue()

    def test_scope_command(self) -> None:
        code, output = self._run(["--config", str(self.config_path), "scope"])
        self.assertEqual(code, 0)
        self.assertIn("demo.apk", output)

    def test_triage_then_sessions_then_report(self) -> None:
        config = ["--config", str(self.config_path)]
        code, output = self._run(config + ["triage", str(self.apk), "--json"])
        self.assertEqual(code, 0, output)
        payload = json.loads(output)
        self.assertEqual(payload["manifest"]["package"], "com.example.demo")

        code, output = self._run(config + ["sessions"])
        self.assertEqual(code, 0)
        self.assertIn("demo.apk", output)

        code, output = self._run(config + ["report", "--target", "latest"])
        self.assertEqual(code, 0)
        self.assertIn("report.md", output)

    def test_scope_refusal_exits_nonzero_with_a_reason(self) -> None:
        other = fixtures.build_manifest_apk(self.root / "other.apk")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code, _ = self._run(["--config", str(self.config_path), "triage", str(other)])
        self.assertEqual(code, cli.EXIT_FAILED)
        self.assertIn("refused", errors.getvalue())

    def test_missing_config_exits_with_usage_error(self) -> None:
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code, _ = self._run(["--config", str(self.root / "absent.toml"), "scope"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("configuration error", errors.getvalue())

    def test_mcp_tools_subcommand_lists_tools(self) -> None:
        code, output = self._run(["--config", str(self.config_path), "mcp", "tools"])
        self.assertEqual(code, 0)
        self.assertIn("revlab_triage_apk", output)


class GhidraToolResolutionTests(unittest.TestCase):
    """Capability -> real tool name, locked against a live server's naming."""

    REAL_TOOL_NAMES = [
        "ghidra_environment", "ghidra_session_status", "ghidra_import_and_analyze",
        "ghidra_open_program", "ghidra_current_program", "ghidra_close_program",
        "ghidra_list_projects", "ghidra_list_programs", "ghidra_list_functions",
        "ghidra_function_details", "ghidra_decompile_function", "ghidra_search_symbols",
        "ghidra_call_graph", "ghidra_disassemble", "ghidra_xrefs", "ghidra_list_strings",
        "ghidra_list_imports", "ghidra_list_entry_points", "ghidra_read_bytes",
        "ghidra_search_bytes", "ghidra_list_data_types", "ghidra_list_memory_blocks",
        "ghidra_headless_import",
    ]

    def _client(self) -> McpStdioClient:
        client = McpStdioClient(["python", "-c", "pass"], label="fake")
        client.tools = [{"name": name} for name in self.REAL_TOOL_NAMES]
        return client

    def test_every_capability_needed_by_the_pipeline_resolves(self) -> None:
        from revlab.ghidra import GhidraMcp

        client = self._client()
        expected = {
            "list_functions": "ghidra_list_functions",
            "decompile": "ghidra_decompile_function",
            "disassemble": "ghidra_disassemble",
            "strings": "ghidra_list_strings",
            "imports": "ghidra_list_imports",
            "xrefs": "ghidra_xrefs",
            "call_graph": "ghidra_call_graph",
            "byte_search": "ghidra_search_bytes",
            "import_program": "ghidra_import_and_analyze",
            "status": "ghidra_session_status",
        }
        for capability, tool in expected.items():
            self.assertEqual(
                client.find_tool(*GhidraMcp.TOOL_CANDIDATES[capability]),
                tool,
                f"{capability} did not resolve to {tool}",
            )

    def test_most_specific_candidate_wins(self) -> None:
        # 'import' also appears in ghidra_list_imports, so ordering matters
        client = self._client()
        from revlab.ghidra import GhidraMcp

        self.assertEqual(
            client.find_tool(*GhidraMcp.TOOL_CANDIDATES["import_program"]),
            "ghidra_import_and_analyze",
        )
        self.assertEqual(
            client.find_tool(*GhidraMcp.TOOL_CANDIDATES["imports"]),
            "ghidra_list_imports",
        )


if __name__ == "__main__":
    unittest.main()
