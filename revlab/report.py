"""Report rendering: the evidence store, read back as something a human reads.

Markdown and HTML are rendered from the same data, so a reviewer can diff the
report, and the HTML is a single self-contained file with no CDN dependency
(which matters when the report leaves this machine).
"""

from __future__ import annotations

import html
import time
from pathlib import Path

from .evidence import Session

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_ZH = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "信息",
}

#: Tag -> what a reader should do next. This is where the report earns its keep:
#: every finding category has a concrete follow-up instead of a shrug.
NEXT_STEPS = {
    "packer": "先用 `revlab dynamic run --hook dex_watch` 观察解密点；零命中同样是结论，记录下来再换路线。",
    "dex": "对 dump 出的 DEX 做静态复核；若无 dump，改用 Ghidra 定位解密函数而不是反复重试 hook。",
    "jni": "把 `jni_boundary` 捕获的绑定三元组喂给 Ghidra，按 native 指针偏移定位函数体。",
    "anti-analysis": "把 hook 提前到检测之前（或用 spawn 模式），确认检测点之后再决定是否绕过。",
    "network": "确认 networkSecurityConfig 与 TLS 版本；自带 TLS 栈需要单独验证补丁状态。",
    "manifest": "核对 AndroidManifest 声明与代码行为是否一致，重点看入口 Application 类。",
    "crypto": "记录加密库版本并对照该版本已公开的问题，作为合规结论而不是猜测。",
    "toolchain": "陈旧编译器提示组件长期未更新，可作为供应链合规问题记录。",
    "symbols": "符号不可用时，改走字符串与交叉引用驱动的定位方式。",
    "attack-surface": "按权限对应的能力审计代码路径（悬浮窗/安装包/无障碍/跨包查询）。",
    "coverage": "覆盖率结论要写进报告：未观测到 ≠ 不存在，但会限制结论强度。",
    "integrity": "签名信息缺失时先确认样本来源，避免把重打包件当成官方构建分析。",
}


def _sorted_findings(session: Session) -> list[dict]:
    order = {name: index for index, name in enumerate(SEVERITY_ORDER)}
    return sorted(
        session.unique_findings,
        key=lambda item: (order.get(item.get("severity", "info"), 99), -float(item.get("confidence", 0))),
    )


def _severity_table(session: Session) -> list[tuple[str, int]]:
    counts = session.summary()["severity"]
    return [(name, counts.get(name, 0)) for name in SEVERITY_ORDER]


def _next_steps(findings: list[dict]) -> list[str]:
    tags = {tag for finding in findings for tag in finding.get("tags", [])}
    steps = [NEXT_STEPS[tag] for tag in NEXT_STEPS if tag in tags]
    return steps or ["未命中任何启发式规则：先补一条基线（manifest + ELF triage），再决定动静态投入。"]


def render_markdown(session: Session) -> str:
    meta = session.meta
    summary = session.summary()
    findings = _sorted_findings(session)
    lines: list[str] = []

    lines.append(f"# RevLab 分析报告 — `{session.target}`\n")
    lines.append(f"- 会话目录：`{session.root}`")
    lines.append(f"- 目标类型：{session.kind}")
    lines.append(f"- 创建时间：{meta.get('created_at', '?')}（重开 {meta.get('reopen_count', 0)} 次）")
    lines.append(f"- 记录 {summary['records']} 条 / 发现 {summary['findings']} 条 "
                 f"(条目 {summary['finding_entries']}) / 产物 {summary['artifacts']} 个")
    lines.append(f"- 覆盖阶段：{', '.join(summary['stages']) or '无'}")
    lines.append(f"- 报告生成：{time.strftime('%Y-%m-%dT%H:%M:%S')}\n")

    lines.append("## 1. 结论摘要\n")
    lines.append("| 严重性 | 数量 |")
    lines.append("| --- | --- |")
    for name, count in _severity_table(session):
        lines.append(f"| {SEVERITY_ZH[name]} ({name}) | {count} |")
    lines.append("")
    if findings:
        lines.append("按严重性排序的发现：\n")
        for finding in findings:
            lines.append(
                f"- **{SEVERITY_ZH.get(finding.get('severity'), finding.get('severity'))}** "
                f"{finding.get('title')} — 置信度 {finding.get('confidence')} "
                f"(`{finding.get('id')}`, 阶段 {finding.get('stage')})"
            )
        lines.append("")

    lines.append("## 2. 发现明细\n")
    if not findings:
        lines.append("（无）\n")
    for finding in findings:
        lines.append(f"### {finding.get('title')}\n")
        lines.append(f"- id：`{finding.get('id')}`｜严重性：{finding.get('severity')}"
                     f"｜置信度：{finding.get('confidence')}｜阶段：{finding.get('stage')}")
        if finding.get("tags"):
            lines.append(f"- 标签：{', '.join(finding['tags'])}")
        if finding.get("detail"):
            lines.append(f"- 说明：{finding['detail']}")
        for item in finding.get("evidence", []):
            lines.append(f"- 证据：`{item}`")
        lines.append("")

    lines.append("## 3. 分析记录\n")
    lines.append("| 时间 | 阶段 | 类型 | 产物 |")
    lines.append("| --- | --- | --- | --- |")
    for record in session.records:
        lines.append(
            f"| {record.get('ts', '?')} | {record.get('stage', '?')} | "
            f"{record.get('kind', '?')} | {record.get('artifact', '-')} |"
        )
    lines.append("")

    artifacts = sorted(session.artifacts_dir.glob("*")) if session.artifacts_dir.is_dir() else []
    lines.append("## 4. 证据产物\n")
    if artifacts:
        for path in artifacts:
            size = path.stat().st_size if path.is_file() else 0
            lines.append(f"- `{path.relative_to(session.root)}`（{size} B）")
    else:
        lines.append("（无）")
    lines.append("")

    lines.append("## 5. 下一步建议\n")
    for step in _next_steps(findings):
        lines.append(f"- {step}")
    lines.append("")

    lines.append("## 6. 范围与免责\n")
    lines.append(
        "本报告只描述对已授权样本所做观测的结果。所有结论都能追溯到 `records.jsonl` / "
        "`findings.jsonl` 中的记录；未经授权不得对第三方软件执行本工具的动态分析能力。"
    )
    lines.append("")
    return "\n".join(lines)


_CSS = """
:root { color-scheme: light dark; }
body { font-family: "Segoe UI", system-ui, sans-serif; margin: 0 auto; max-width: 60rem;
       padding: 2rem 1.5rem; line-height: 1.6; }
h1 { font-size: 1.6rem; } h2 { margin-top: 2rem; border-bottom: 2px solid #8884; padding-bottom: .3rem; }
h3 { margin-bottom: .2rem; font-size: 1.05rem; }
code, pre { font-family: Consolas, "Courier New", monospace; }
.size { font-size: .9rem; color: #666; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
th, td { border: 1px solid #8884; padding: .35rem .6rem; text-align: left; font-size: .92rem; }
.finding { border-left: 5px solid #999; padding: .6rem .9rem; margin: .9rem 0; background: #8881; }
.critical { border-color: #b00020; } .high { border-color: #d84315; }
.medium { border-color: #f9a825; } .low { border-color: #2e7d32; } .info { border-color: #607d8b; }
ul { margin: .3rem 0 .6rem 1.2rem; } li { margin: .15rem 0; }
"""


def render_html(session: Session) -> str:
    meta = session.meta
    summary = session.summary()
    findings = _sorted_findings(session)
    escape = html.escape

    def row(cells: list[str]) -> str:
        return "<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in cells) + "</tr>"

    severity_rows = "".join(
        f"<tr><td>{SEVERITY_ZH[name]} ({name})</td><td>{count}</td></tr>"
        for name, count in _severity_table(session)
    )
    finding_blocks = []
    for finding in findings:
        evidence = "".join(
            f"<li><code>{escape(str(item))}</code></li>" for item in finding.get("evidence", [])
        )
        finding_blocks.append(
            f'<div class="finding {escape(str(finding.get("severity")))}">'
            f"<h3>{escape(str(finding.get('title')))}</h3>"
            f'<p class="size">id <code>{escape(str(finding.get("id")))}</code> · '
            f"严重性 {escape(str(finding.get('severity')))} · "
            f"置信度 {escape(str(finding.get('confidence')))} · "
            f"阶段 {escape(str(finding.get('stage')))}</p>"
            + (f"<p>{escape(str(finding['detail']))}</p>" if finding.get("detail") else "")
            + (f"<ul>{evidence}</ul>" if evidence else "")
            + "</div>"
        )

    record_rows = "".join(
        row([record.get("ts", "?"), record.get("stage", "?"), record.get("kind", "?"),
             record.get("artifact", "-")])
        for record in session.records
    )
    artifact_items = "".join(
        f"<li><code>{escape(str(path.relative_to(session.root)))}</code>"
        f" ({path.stat().st_size if path.is_file() else 0} B)</li>"
        for path in (sorted(session.artifacts_dir.glob("*")) if session.artifacts_dir.is_dir() else [])
    )
    steps = "".join(f"<li>{escape(step)}</li>" for step in _next_steps(findings))

    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>RevLab 报告 — {escape(session.target)}</title>
<style>{_CSS}</style></head><body>
<h1>RevLab 分析报告 — <code>{escape(session.target)}</code></h1>
<p class="size">会话目录 <code>{escape(str(session.root))}</code><br>
类型 {escape(session.kind)} · 创建 {escape(str(meta.get('created_at', '?')))}
（重开 {escape(str(meta.get('reopen_count', 0)))} 次）<br>
记录 {summary['records']} 条 · 发现 {summary['findings']} 条 · 产物 {summary['artifacts']} 个<br>
阶段 {escape(', '.join(summary['stages']) or '无')} · 生成 {time.strftime('%Y-%m-%dT%H:%M:%S')}</p>

<h2>1. 结论摘要</h2>
<table><tr><th>严重性</th><th>数量</th></tr>{severity_rows}</table>

<h2>2. 发现明细</h2>
{''.join(finding_blocks) or '<p>（无）</p>'}

<h2>3. 分析记录</h2>
<table><tr><th>时间</th><th>阶段</th><th>类型</th><th>产物</th></tr>{record_rows}</table>

<h2>4. 证据产物</h2>
<ul>{artifact_items or '<li>（无）</li>'}</ul>

<h2>5. 下一步建议</h2>
<ul>{steps}</ul>

<h2>6. 范围与免责</h2>
<p>本报告只描述对已授权样本所做观测的结果；所有结论都能追溯到
<code>records.jsonl</code> / <code>findings.jsonl</code>。未经授权不得对第三方软件执行
本工具的动态分析能力。</p>
</body></html>
"""


def write_report(session: Session, markdown: bool = True, html: bool = True) -> list[Path]:
    """Write report files into the session directory; return what was written."""
    written: list[Path] = []
    if markdown:
        path = session.root / "report.md"
        path.write_text(render_markdown(session), encoding="utf-8", newline="\n")
        written.append(path)
    if html:
        path = session.root / "report.html"
        path.write_text(render_html(session), encoding="utf-8", newline="\n")
        written.append(path)
    return written
