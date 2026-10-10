"""End-to-end orchestration: the analysis passes and the report.

The CLI, the local web UI and the MCP server are thin shells over these
functions, which is what keeps behaviour identical no matter how the tool is
driven -- a human typing, a browser clicking, or an assistant calling tools.

Every pass follows the same contract: open (or reuse) a session, run one engine,
write records and findings, return a plain dict a caller can print or hand on.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import elf, heuristics, static_apk
from .config import Config
from .evidence import Finding, Session, latest_session, list_sessions

NATIVE_PATTERNS = ("lib/*/*.so", "lib/*/*.so.*")


def _json(payload) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"


def open_session(config: Config, target: str, kind: str = "unknown",
                 notes: str = "") -> Session:
    """Session for a target, reusing the directory when it already exists."""
    return Session.open(config.workspace_for(target), target, kind=kind, notes=notes)


def session_for(config: Config, path_or_latest: str | None = None) -> Session:
    """Resolve a session from a workspace path, a target path, or 'latest'."""
    if path_or_latest and path_or_latest != "latest":
        path = Path(path_or_latest)
        if (path / "session.json").exists():
            meta = json.loads((path / "session.json").read_text(encoding="utf-8"))
            return Session(path, meta.get("target", path.name), meta.get("kind", "unknown"))
        return open_session(config, str(path), kind="unknown")
    session = latest_session(config.workspace_root)
    if session is None:
        raise FileNotFoundError(
            f"no sessions under {config.workspace_root}; run `revlab triage <apk>` first"
        )
    return session


def list_workspaces(config: Config) -> list[dict]:
    return [session.summary() for session in list_sessions(config.workspace_root)]


# ---- pass 1: static triage -------------------------------------------------
def static_triage(config: Config, apk: str | Path, extract: bool = True,
                  abi_preference: str = "", run_elf: bool = True) -> dict:
    """Probe an APK, extract what deserves a closer look, interpret the result."""
    config.require_authorised(str(apk))
    session = open_session(config, str(apk), kind="apk")
    probe = static_apk.probe_apk(apk)

    if probe.get("error"):
        session.record("static", "apk-probe-failed", probe)
        findings = heuristics.apk_findings(probe)
        for finding in findings:
            session.find(finding)
        return {"session": str(session.root), "error": probe["error"], "findings": len(findings)}

    session.save_artifact("apk-probe.json", _json(probe))
    session.record(
        "static",
        "apk-probe",
        {
            "file": probe["file"],
            "manifest": probe["manifest"],
            "flags": probe["flags"],
            "dex": probe["dex"],
            "entry_count": len(probe["entries"]),
            "assets": {"count": probe["assets"]["count"], "bytes": probe["assets"]["bytes"]},
        },
        artifact="apk-probe.json",
    )
    findings = heuristics.apk_findings(probe)
    for finding in findings:
        session.find(finding)

    extracted: dict[str, list[str]] = {}
    elf_infos: list[elf.ElfInfo] = []
    if extract:
        libs_dir = session.artifacts_dir / "native"
        libs = static_apk.extract_members(apk, NATIVE_PATTERNS, libs_dir)
        extracted["native"] = [str(path.relative_to(session.root)) for path in libs]
        dex_dir = session.artifacts_dir / "dex"
        dex_files = static_apk.extract_members(apk, ("classes*.dex",), dex_dir)
        extracted["dex"] = [str(path.relative_to(session.root)) for path in dex_files]
        session.record("static", "extracted", extracted)

        if run_elf and libs:
            preferred = [
                path for path in libs if abi_preference and abi_preference in str(path)
            ] or libs
            elf_infos = [elf.parse(path) for path in preferred if path.is_file()]
            summary = elf.summarize(elf_infos)
            session.save_artifact(
                "elf-triage.json",
                _json({"summary": summary, "objects": [info.to_dict() for info in elf_infos]}),
            )
            session.record("static", "elf-triage", summary, artifact="elf-triage.json")
            for finding in heuristics.elf_findings(elf_infos, summary):
                session.find(finding)

    return {
        "session": str(session.root),
        "target": session.target,
        "manifest": probe["manifest"],
        "flags": probe["flags"],
        "dex": probe["dex"],
        "elf": elf.summarize(elf_infos) if elf_infos else {},
        "extracted": {key: len(value) for key, value in extracted.items()},
        "findings": len(session.findings),
        "severity": session.summary()["severity"],
    }


def elf_triage(config: Config, root: str | Path, authorised_target: str = "") -> dict:
    """Triage a directory (or one file) of native objects without an APK.

    Handing this pass a single file that is *not* ELF is a mistake worth naming:
    the result then carries an ``error`` explaining what the file actually is and
    which command reads it. "0 objects, no findings" would read like "this binary
    is empty" and send the operator looking for a problem that does not exist.
    """
    config.require_authorised(authorised_target or str(root))
    target = Path(root)
    if not target.exists():
        raise FileNotFoundError(f"path not found: {target}")

    session = open_session(config, str(root), kind="native-dir")
    result = elf.triage(root)
    infos = result.objects
    summary = elf.summarize(infos)
    skipped = [item.to_dict() for item in result.skipped]
    session.save_artifact(
        "elf-triage.json",
        _json({
            "summary": summary,
            "objects": [info.to_dict() for info in infos],
            "skipped": skipped,
        }),
    )
    session.record(
        "static", "elf-triage", {**summary, "skipped": len(skipped)},
        artifact="elf-triage.json",
    )
    findings = heuristics.elf_findings(infos, summary)
    for finding in findings:
        session.find(finding)

    payload = {
        "session": str(session.root),
        "target": session.target,
        "summary": summary,
        "skipped": skipped,
        "findings": [finding.to_dict() for finding in findings],
    }
    unsupported = result.unsupported_reason
    if unsupported:
        payload["error"] = unsupported
        session.record(
            "static", "not-analysable",
            {"path": skipped[0]["path"], "kind": skipped[0]["kind"], "reason": unsupported},
        )
    return payload


# ---- pass 2: Ghidra --------------------------------------------------------
def ghidra_pass(config: Config, session: Session, binary: str | Path,
                name_filter: str = "", max_functions: int = 40,
                via: str = "auto") -> dict:
    """Ask Ghidra about one binary, over MCP when possible, headless otherwise."""
    from .ghidra import GhidraError, GhidraHeadless, GhidraMcp

    target = Path(binary)
    if not target.exists():
        raise FileNotFoundError(f"binary not found: {target}")

    result: dict = {"binary": str(target), "via": via}

    if via in ("auto", "mcp"):
        try:
            with GhidraMcp(config) as mcp:
                description = mcp.describe()
                session.record("ghidra", "mcp-capabilities", description)
                result["mcp"] = {
                    "server_info": description["server_info"],
                    "tool_count": description["tool_count"],
                    "capabilities_resolved": description["capabilities_resolved"],
                    "missing_capabilities": description["missing_capabilities"],
                }
            if via == "mcp":
                return result
        except Exception as exc:  # noqa: BLE001 - any MCP failure falls back to headless
            result["mcp_error"] = f"{type(exc).__name__}: {exc}"
            session.record("ghidra", "mcp-unavailable", result["mcp_error"])
            if via == "mcp":
                raise

    if via in ("auto", "headless"):
        headless = GhidraHeadless(config)
        out_file = session.root / f"ghidra-{target.stem[:32]}.json"
        try:
            run = headless.summary(
                target, out_file, name_filter=name_filter, max_functions=max_functions
            )
        except GhidraError as exc:
            session.record("ghidra", "headless-unavailable", str(exc))
            result["headless_error"] = str(exc)
            return result
        session.record(
            "ghidra",
            "headless-run",
            {
                "project": run["project_name"],
                "returncode": run["returncode"],
                "ok": run["ok"],
                "summary_written": run["summary_written"],
                "stdout_tail": run["stdout_tail"][-1500:],
            },
        )
        result["headless"] = {
            "project": run["project_name"],
            "ok": run["ok"],
            "summary_written": run["summary_written"],
        }
        if out_file.exists():
            try:
                summary = json.loads(out_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                summary = {}
            result["summary"] = {
                "program": summary.get("program"),
                "function_count": summary.get("function_count"),
                "decompiled_count": summary.get("decompiled_count"),
                "strings": len(summary.get("strings", [])),
                "imports": summary.get("imports", [])[:20],
            }
            session.find(
                Finding(
                    id="ghidra-summary",
                    title=f"Ghidra 摘要已生成（{summary.get('function_count', '?')} 个函数）",
                    severity="info",
                    stage="ghidra",
                    detail=(
                        f"反编译 {summary.get('decompiled_count', 0)} 个高引用函数，"
                        f"收录 {len(summary.get('strings', []))} 条字符串；"
                        f"完整结果见 artifacts/{out_file.name}"
                    ),
                    evidence=[out_file.name],
                    confidence=0.95,
                    tags=["ghidra"],
                )
            )
    return result


# ---- pass 3: Frida ---------------------------------------------------------
def dynamic_pass(config: Config, session: Session, target: str, hook: str,
                 seconds: float = 30.0, mode: str = "attach",
                 serial: str | None = None) -> dict:
    """Run one hook against one target and write the result into the session."""
    from .frida_dyn import FridaError, run_hook

    config.require_authorised(target)
    jsonl = session.artifacts_dir / f"frida-{hook.replace('.js', '')}.jsonl"
    try:
        result = run_hook(
            config,
            target=target,
            hook_name=hook,
            seconds=seconds,
            mode=mode,
            serial=serial,
            output=jsonl,
        )
    except FridaError as exc:
        session.record("dynamic", "frida-unavailable", str(exc))
        return {"error": str(exc), "hook": hook, "target": target}

    session.record(
        "dynamic",
        "hook-run",
        {
            "hook": result["hook"],
            "target": target,
            "mode": mode,
            "pid": result["pid"],
            "seconds": seconds,
            "total": result["total"],
            "by_tag": result["by_tag"],
            "errors": result["errors"],
            "detached": result["detached"],
            "note": result.get("note"),
        },
        artifact=jsonl.name,
    )
    for finding in _dynamic_findings(result, jsonl):
        session.find(finding)
    result["session"] = str(session.root)
    return result


def _dynamic_findings(result: dict, jsonl: Path) -> list[Finding]:
    """Turn hook output into findings, including the empty-result case."""
    out: list[Finding] = []
    tags = result.get("by_tag", {})
    name = result["hook"]

    if result.get("detached"):
        out.append(
            Finding(
                id=f"frida-detached-{name}",
                title="会话在观测窗口结束前被断开",
                severity="medium",
                stage="dynamic",
                detail=(
                    f"detach 原因：{result['detached'].get('reason', 'unknown')}；"
                    "多数情况下这是反调试或崩溃，而不是脚本问题"
                ),
                evidence=[jsonl.name],
                confidence=0.7,
                tags=["dynamic", "anti-analysis"],
            )
        )

    if tags.get("dex-write") or tags.get("dex-dumped"):
        detail = (
            f"dex-write={tags.get('dex-write', 0)}, dex-dumped={tags.get('dex-dumped', 0)}；"
            "说明运行期确实在改写 DEX 数据（或应用在被跟踪时也会这样做）"
        )
        out.append(
            Finding(
                id=f"runtime-dex-writes-{name}",
                title="运行期检测到 DEX 形态数据的写入",
                severity="high",
                stage="dynamic",
                detail=detail,
                evidence=[jsonl.name],
                confidence=0.75,
                tags=["unpack", "dex"],
            )
        )

    if tags.get("register-natives"):
        out.append(
            Finding(
                id=f"runtime-jni-bindings-{name}",
                title="捕获到 RegisterNatives 绑定（静态符号表里看不到的 JNI 面）",
                severity="medium",
                stage="dynamic",
                detail=(
                    f"{tags['register-natives']} 次绑定调用；"
                    "导出的 name/signature/native 三元组可直接用于定位 Ghidra 函数"
                ),
                evidence=[jsonl.name],
                confidence=0.9,
                tags=["jni", "dynamic"],
            )
        )

    anti = {
        tag: count
        for tag, count in tags.items()
        if tag in ("ptrace", "ptrace-other", "self-check", "process-control", "system-exit")
    }
    if anti:
        out.append(
            Finding(
                id=f"anti-analysis-observed-{name}",
                title="观测到自检/反调试行为",
                severity="medium",
                stage="dynamic",
                detail=(
                    "触发点："
                    + ", ".join(f"{tag}x{count}" for tag, count in sorted(anti.items()))
                    + "；把 hook 安装在检测之前，或选择这些检测不到的路径"
                ),
                evidence=[jsonl.name],
                confidence=0.7,
                tags=["anti-analysis", "dynamic"],
            )
        )

    if result.get("total") == 0:
        out.append(
            Finding(
                id=f"hook-silent-{name}",
                title=f"hook {name} 已加载但没有任何输出",
                severity="info",
                stage="dynamic",
                detail=(
                    "覆盖率为零是一个有效结论：要么该 API 在这台设备/架构上不可达，"
                    "要么目标未走到这段代码。把这条记录写进证据，别重复试第二次"
                ),
                evidence=[jsonl.name],
                confidence=0.8,
                tags=["coverage"],
            )
        )
    return out


# ---- reporting -------------------------------------------------------------
def build_report(config: Config, session: Session | None = None,
                 target: str | None = None, markdown: bool = True,
                 html: bool = True) -> dict:
    """Render the session's evidence into report files."""
    from .report import write_report

    session = session or session_for(config, target)
    written = write_report(session, markdown=markdown, html=html)
    return {"session": str(session.root), "written": [str(path) for path in written]}
