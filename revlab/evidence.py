"""Evidence store: every stage writes JSON, the report reads it back.

One *session* is one directory under a target's workspace:

```
workspaces/<target>-<digest>/
  session.json      session metadata (target, tool versions, timestamps)
  records.jsonl     append-only: one analysis record per line ("what ran")
  findings.jsonl    append-only: one finding per line ("what it means")
  artifacts/        large outputs: decompiled C, dumped DEX, logs
  report.md|.html
```

Records and findings answer different questions, so they are separate files:
records are raw tool output, findings are interpretations with a severity and a
confidence. A report can therefore be regenerated when an interpretation
changes without re-running anything.
"""

from __future__ import annotations

import json
import platform
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file, tolerating (and marking) a truncated last line."""
    path = Path(path)
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"stage": "corrupt", "kind": "unparsable-line", "raw": line[:400]})
    return out


def dedupe_findings(findings: list[dict]) -> list[dict]:
    """Latest occurrence per id wins.

    The log stays append-only (re-running a pass is evidence too), but a report
    that counted the same finding three times because the operator ran triage
    three times would be worse than useless. Reading collapses duplicates; the
    JSONL keeps them.
    """
    latest: dict[str, dict] = {}
    for item in findings:
        key = str(item.get("id") or item.get("title") or "")
        latest[key] = item
    return list(latest.values())


@dataclass
class Finding:
    """An interpreted observation -- the thing a human actually reads."""

    id: str
    title: str
    severity: str = "info"
    detail: str = ""
    stage: str = "static"
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["confidence"] = round(float(self.confidence), 2)
        return payload


class Session:
    """One target, one directory, one append-only evidence trail."""

    def __init__(self, root: Path, target: str, kind: str = "unknown", notes: str = ""):
        self.root = Path(root)
        self.target = target
        self.kind = kind
        self.notes = notes
        self.root.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.root / "session.json"
        self.records_path = self.root / "records.jsonl"
        self.findings_path = self.root / "findings.jsonl"
        self.artifacts_dir = self.root / "artifacts"

    # ---- lifecycle ---------------------------------------------------------
    @classmethod
    def open(cls, root: Path, target: str, **kwargs) -> "Session":
        session = cls(root, target, **kwargs)
        if not session.meta_path.exists():
            session.write_meta()
        else:
            meta = session.meta
            meta["reopened_at"] = _now()
            meta["reopen_count"] = int(meta.get("reopen_count", 0)) + 1
            session.meta_path.write_text(
                json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        return session

    def write_meta(self) -> None:
        meta = {
            "target": self.target,
            "kind": self.kind,
            "notes": self.notes,
            "created_at": _now(),
            "session_id": secrets.token_hex(6),
            "host": {
                "platform": platform.platform(),
                "python": sys.version.split()[0],
            },
            "reopen_count": 0,
        }
        self.meta_path.write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    # ---- writes ------------------------------------------------------------
    def record(self, stage: str, kind: str, data, **extra) -> dict:
        payload = {"ts": _now(), "stage": stage, "kind": kind, "data": data, **extra}
        _append_jsonl(self.records_path, payload)
        return payload

    def find(self, finding: Finding) -> Finding:
        _append_jsonl(self.findings_path, finding.to_dict())
        return finding

    def add_finding(self, id: str, title: str, **kwargs) -> Finding:
        return self.find(Finding(id=id, title=title, **kwargs))

    def save_artifact(self, name: str, content: str | bytes) -> Path:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = self.artifacts_dir / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
        return path

    # ---- reads -------------------------------------------------------------
    @property
    def meta(self) -> dict:
        if not self.meta_path.exists():
            return {}
        return json.loads(self.meta_path.read_text(encoding="utf-8"))

    @property
    def records(self) -> list[dict]:
        return read_jsonl(self.records_path)

    @property
    def findings(self) -> list[dict]:
        return read_jsonl(self.findings_path)

    def records_of(self, stage: str | None = None) -> list[dict]:
        return [r for r in self.records if stage is None or r.get("stage") == stage]

    @property
    def unique_findings(self) -> list[dict]:
        """Findings with duplicates collapsed (latest per id) -- what a report shows."""
        return dedupe_findings(self.findings)

    def summary(self) -> dict:
        records = self.records
        findings = self.unique_findings
        counts = {sev: 0 for sev in SEVERITIES}
        for item in findings:
            severity = item.get("severity", "info")
            counts[severity] = counts.get(severity, 0) + 1
        return {
            "workspace": str(self.root),
            "target": self.target,
            "kind": self.kind,
            "records": len(records),
            "findings": len(findings),
            "finding_entries": len(self.findings),
            "stages": sorted({r.get("stage", "?") for r in records}),
            "severity": counts,
            "artifacts": (
                len([p for p in self.artifacts_dir.glob("*") if p.is_file()])
                if self.artifacts_dir.is_dir()
                else 0
            ),
        }


def list_sessions(workspace_root: Path) -> list[Session]:
    """Every session under a workspace root, newest first."""
    root = Path(workspace_root)
    if not root.is_dir():
        return []
    found: list[tuple[float, Session]] = []
    for entry in root.iterdir():
        meta_path = entry / "session.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        found.append(
            (
                meta_path.stat().st_mtime,
                Session(entry, meta.get("target", entry.name), meta.get("kind", "unknown")),
            )
        )
    return [session for _, session in sorted(found, key=lambda pair: pair[0], reverse=True)]


def latest_session(workspace_root: Path) -> Session | None:
    sessions = list_sessions(workspace_root)
    return sessions[0] if sessions else None
