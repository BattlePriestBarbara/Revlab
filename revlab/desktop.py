"""The desktop window: RevLab as something you can double-click.

The same rule as the CLI, the web UI and the MCP server applies here: this file
holds no analysis logic. A button collects its inputs on the UI thread, hands a
closure to a worker thread, and the closure calls one function from
:mod:`revlab.pipeline`. Everything else in here is presentation, plus the two
things a double-clicked executable needs and a command never does:

* **a configuration**. A frozen build has no ``revlab.toml`` to start from, so
  the first run writes the template next to the program and shows where it went;
* **somewhere for output**. A windowed build has no console, so ``stdout`` and
  ``stderr`` go to a log file, and every failure is also shown in a dialog --
  a GUI that dies silently is worse than a CLI that dies loudly.

Long operations run off the UI thread and report back through a queue polled
with ``after()``; the widgets are only ever touched from the main thread.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import socket
import sys
import tempfile
import threading
import traceback
import webbrowser
import zipfile
from dataclasses import dataclass
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__, demo, elf
from .config import (
    CONFIG_NAME,
    Config,
    ConfigError,
    ScopeError,
    load_config,
    set_authorised,
    write_default_config,
)
from .doctor import format_doctor, run_doctor
from .pipeline import (
    build_report,
    elf_triage,
    ghidra_pass,
    list_workspaces,
    open_session,
    session_for,
    static_triage,
)

APP_NAME = "RevLab"
LOG_NAME = "revlab-desktop.log"
SAMPLE_RELATIVE = Path("samples") / "demo.apk"


# ---- the parts that need no display, so the tests can reach them ------------
def app_dir() -> Path:
    """Where the program lives: next to the ``.exe`` once frozen."""
    if getattr(sys, "frozen", False):  # PyInstaller sets sys.frozen
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def default_config_path() -> Path:
    return app_dir() / CONFIG_NAME


def default_workspace() -> Path:
    return app_dir() / "workspaces"


def sample_dir() -> Path:
    """Where the synthetic sample is written: next to the program, else temp.

    The first choice keeps everything a user produces in one visible place; the
    fallback covers a program installed somewhere read-only.
    """
    preferred = app_dir() / "samples"
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".writable"
        probe.write_bytes(b"")
        probe.unlink()
        return preferred
    except OSError:
        fallback = Path(tempfile.gettempdir()) / APP_NAME / "samples"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def log_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or str(app_dir())
    return Path(base) / APP_NAME / "logs" / LOG_NAME


def redirect_output() -> Path:
    """Send stdout/stderr to a log file and return it.

    A windowed program cannot print anywhere; without this, an exception inside
    a worker thread would leave no trace at all.
    """
    target = log_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    stream = open(target, "a", encoding="utf-8", buffering=1)
    sys.stdout = stream
    sys.stderr = stream
    return target


def bootstrap_config(
    explicit: str | os.PathLike | None = None,
) -> tuple[Config, Path, list[str]]:
    """Find the configuration, creating a usable one on first run.

    Returns the loaded config, the path the window writes scope changes to, and
    notes worth showing the operator.
    """
    if explicit:
        path = Path(explicit)
        return load_config(path), path, [f"config: {path}"]

    path = default_config_path()
    if path.exists():
        return load_config(path), path, [f"config: {path}"]

    write_default_config(path)
    config = load_config(path)
    notes = [
        f"首次运行：已写入配置文件 {path}",
        "  留空的路径表示自动探测；[scope] 是授权名单，动态分析只对名单内的目标生效",
    ]
    template = app_dir() / "revlab.toml.example"
    if template.exists():
        notes.append(f"  带注释的模板：{template}")
    return config, path, notes


def sniff_kind(target: Path) -> str:
    """What this file actually is -- by content, not by extension.

    An APK is a zip that carries ``AndroidManifest.xml``; anything else that
    starts with ``PK`` is just a zip, and saying so beats guessing from a name.
    """
    kind = elf.sniff(target)
    if kind == "zip" and zipfile.is_zipfile(target):
        try:
            with zipfile.ZipFile(target) as archive:
                if "AndroidManifest.xml" in archive.namelist():
                    return "apk"
        except (zipfile.BadZipFile, OSError):
            return kind
    return kind


@dataclass(frozen=True)
class Plan:
    """What will be run for a chosen file, and why."""

    kind: str
    label: str
    stage: str          # apk | elf | ghidra | none
    note: str


_KINDS = {
    "apk": ("Android APK", "apk", "静态三连：解包 + 清单 + 原生库"),
    "elf": ("ELF 原生库/可执行文件", "elf", "自研 ELF 解析，不用外部引擎"),
    "pe": ("Windows PE/COFF", "ghidra", "Ghidra 可直接读取 PE"),
    "dex": ("Dalvik DEX", "ghidra", "Ghidra 可读取 DEX"),
    "mach-o-64": ("Mach-O 64", "ghidra", "Ghidra 可读取 Mach-O"),
    "mach-o-32": ("Mach-O 32", "ghidra", "Ghidra 可读取 Mach-O"),
    "mach-o-64-le": ("Mach-O 64 (LE)", "ghidra", "Ghidra 可读取 Mach-O"),
    "mach-o-32-le": ("Mach-O 32 (LE)", "ghidra", "Ghidra 可读取 Mach-O"),
    "mach-o-universal": ("Mach-O 通用包", "none", "fat 二进制：先抽出单个 slice 再分析"),
}


def plan_for(path: str | os.PathLike) -> Plan:
    """Decide the stage for a target, and say what the operator should expect."""
    target = Path(path)
    if not target.exists():
        return Plan("missing", "文件不存在", "none", f"{target} 不存在")
    if target.is_dir():
        return Plan("directory", "目录", "elf", "对目录内每个原生对象做 ELF 三连")
    kind = sniff_kind(target)
    label, stage, note = _KINDS.get(
        kind, (kind, "none", elf.NEXT_STEP.get(kind, "无法识别的格式"))
    )
    return Plan(kind, label, stage, note)


def summarise(payload, prefix: str = "") -> list[str]:
    """Scalars as ``key: value``, containers as sizes: readable at a glance."""
    lines: list[str] = []
    for key, value in payload.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.extend(summarise(value, prefix + "  "))
        elif isinstance(value, (list, tuple)):
            heads = ""
            if value and not isinstance(value[0], (dict, list)):
                heads = " [" + ", ".join(str(item) for item in value[:5]) + "]"
            lines.append(f"{prefix}{key}: {len(value)} item(s){heads}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return lines


def lan_address() -> str:
    """The address a phone on the same network should use.

    Opens a UDP socket towards a public address to learn which local interface
    would carry that traffic -- no packet is sent, nothing connects.
    """
    for probe in (("8.8.8.8", 53), ("192.168.1.1", 53)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(probe)
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def free_port(preferred: int = 8765) -> int:
    """*preferred* if it is free, otherwise whatever the OS offers."""
    for candidate in (preferred, 0):
        sock = socket.socket()
        try:
            sock.bind(("127.0.0.1", candidate))
            return int(sock.getsockname()[1])
        except OSError:
            continue
        finally:
            sock.close()
    return preferred


def run_plan(
    config: Config,
    plan: Plan,
    target: Path,
    *,
    extract: bool = True,
    abi: str = "",
    name_filter: str = "",
    max_functions: int = 40,
) -> tuple[Path | None, dict]:
    """Execute one plan and return ``(workspace, result)``. No Tk objects here."""
    if plan.stage == "apk":
        result = static_triage(config, str(target), extract=extract, abi_preference=abi)
        workspace = Path(result["session"]) if result.get("session") else None
        return workspace, result

    if plan.stage == "elf":
        result = elf_triage(config, str(target))
        workspace = Path(result["session"]) if result.get("session") else None
        return workspace, result

    if plan.stage == "ghidra":
        session = open_session(config, str(target), kind="binary")
        result = ghidra_pass(
            config, session, str(target), name_filter=name_filter,
            max_functions=max_functions,
        )
        return session.root, result

    return None, {"error": plan.note, "kind": plan.kind, "target": str(target)}


class Window:
    """The whole UI. Buttons collect inputs, workers call the pipeline."""

    def __init__(self, root: tk.Tk, config: Config, config_path: Path,
                 log_file: Path, notes: list[str]) -> None:
        self.root = root
        self.config = config
        self.config_path = config_path
        self.log_file = log_file
        self.jobs: queue.Queue = queue.Queue()
        self.busy = False
        self.last_workspace: Path | None = None
        self.written: list[Path] = []
        self.finding_detail: dict[str, str] = {}

        root.title(f"{APP_NAME} {__version__} — Ghidra + Frida 逆向工程工作台")
        root.geometry("1120x760")
        root.minsize(900, 600)
        self._variables()
        self._layout()
        self._poll()

        for note in notes:
            self.log(note)
        self.log(f"workspace: {config.workspace_root}")
        self.log(f"日志文件  : {log_file}")
        self.refresh_scope()
        self.refresh_sessions()
        self.status("就绪")

    # ---- construction ------------------------------------------------------
    def _variables(self) -> None:
        self.target = tk.StringVar()
        self.abi = tk.StringVar(value="")
        self.filter = tk.StringVar(value="")
        self.maxfun = tk.StringVar(value="40")
        self.extract = tk.BooleanVar(value=True)
        self.kind = tk.StringVar(value="（未选择目标）")
        self.status_var = tk.StringVar(value="")
        self.scope_entry = tk.StringVar()
        self.target.trace_add("write", lambda *_: self._update_kind())

    def _layout(self) -> None:
        top = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        top.pack(fill="x")

        ttk.Label(top, text="目标").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.target).grid(
            row=0, column=1, columnspan=5, sticky="ew", padx=(6, 6)
        )
        ttk.Button(top, text="浏览…", command=self.pick_target).grid(row=0, column=6)
        ttk.Button(top, text="生成合成样本", command=self.make_sample).grid(
            row=0, column=7, padx=(6, 0)
        )
        ttk.Label(top, textvariable=self.kind, foreground="#555").grid(
            row=1, column=1, columnspan=7, sticky="w", pady=(2, 0)
        )

        ttk.Label(top, text="ABI").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(top, textvariable=self.abi, width=10).grid(
            row=2, column=1, sticky="w", padx=(6, 12), pady=(6, 0)
        )
        ttk.Checkbutton(top, text="解包原生库与 DEX", variable=self.extract).grid(
            row=2, column=2, columnspan=2, sticky="w", pady=(6, 0)
        )
        ttk.Label(top, text="函数过滤").grid(row=2, column=4, sticky="e", pady=(6, 0))
        ttk.Entry(top, textvariable=self.filter, width=16).grid(
            row=2, column=5, sticky="w", padx=(6, 12), pady=(6, 0)
        )
        ttk.Label(top, text="最多函数").grid(row=2, column=6, sticky="e", pady=(6, 0))
        ttk.Entry(top, textvariable=self.maxfun, width=6).grid(
            row=2, column=7, sticky="w", padx=(6, 0), pady=(6, 0)
        )
        top.columnconfigure(5, weight=1)

        actions = ttk.Frame(self.root, padding=(10, 0, 10, 6))
        actions.pack(fill="x")
        for index, (text, command) in enumerate((
            ("开始分析", self.analyze),
            ("Ghidra 反编译", self.ghidra),
            ("生成报告", self.report),
            ("打开报告", self.open_report),
            ("打开产物目录", self.open_workspace),
            ("共享给浏览器/手机", self.share),
            ("环境体检", self.doctor),
        )):
            style = "primary.TButton" if index == 0 else "TButton"
            ttk.Button(actions, text=text, command=command, style=style).grid(
                row=0, column=index, padx=(0, 6)
            )

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self._tab_findings()
        self._tab_doctor()
        self._tab_scope()
        self._tab_sessions()

        bar = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        bar.pack(fill="x")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        ttk.Label(bar, text=f"配置 {self.config_path}", foreground="#666").pack(side="right")

    def _tab_findings(self) -> None:
        outer = ttk.Frame(self.notebook)
        self.notebook.add(outer, text="发现与输出")
        panes = ttk.Panedwindow(outer, orient="vertical")
        panes.pack(fill="both", expand=True)

        holder = ttk.Frame(panes)
        self.findings = ttk.Treeview(
            holder, columns=("severity", "title", "confidence", "stage"),
            show="headings", height=12,
        )
        for column, text, width in (
            ("severity", "严重性", 90), ("title", "发现", 520),
            ("confidence", "置信度", 90), ("stage", "阶段", 130),
        ):
            self.findings.heading(column, text=text)
            self.findings.column(column, width=width, anchor="w")
        for severity, colour in (
            ("critical", "#b00020"), ("high", "#d84315"), ("medium", "#b26a00"),
            ("low", "#2e7d32"), ("info", "#546e7a"),
        ):
            self.findings.tag_configure(severity, foreground=colour)
        scroll = ttk.Scrollbar(holder, orient="vertical", command=self.findings.yview)
        self.findings.configure(yscrollcommand=scroll.set)
        self.findings.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.findings.bind("<<TreeviewSelect>>", self._show_selected_finding)
        panes.add(holder, weight=3)

        logholder = ttk.Frame(panes)
        self.logbox = tk.Text(logholder, wrap="none", height=14, font=("Consolas", 9))
        logscroll = ttk.Scrollbar(logholder, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=logscroll.set, state="disabled")
        self.logbox.pack(side="left", fill="both", expand=True)
        logscroll.pack(side="right", fill="y")
        panes.add(logholder, weight=2)

    def _tab_doctor(self) -> None:
        outer = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(outer, text="环境体检")
        ttk.Button(outer, text="重新体检", command=self.doctor).pack(anchor="w")
        self.doctorbox = tk.Text(outer, wrap="word", font=("Consolas", 9), state="disabled")
        self.doctorbox.pack(fill="both", expand=True, pady=(6, 0))

    def _tab_scope(self) -> None:
        outer = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(outer, text="授权范围")
        ttk.Label(
            outer,
            text=("动态分析（Frida）只对这里的名单生效：包名、应用名或文件名片段，"
                  "大小写不敏感。名单为空时一切接触目标的操作都会被拒绝——这是刻意的默认。"),
            wraplength=980, foreground="#444",
        ).pack(anchor="w")
        row = ttk.Frame(outer, padding=(0, 8, 0, 0))
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.scope_entry, width=40).pack(side="left")
        ttk.Button(row, text="添加", command=self.scope_add).pack(side="left", padx=4)
        ttk.Button(row, text="移除选中", command=self.scope_remove).pack(side="left", padx=4)
        ttk.Button(row, text="保存到配置", command=self.scope_save).pack(side="left", padx=4)
        ttk.Button(row, text="重新载入", command=self.refresh_scope).pack(side="left", padx=4)
        self.scopelist = tk.Listbox(outer, height=12)
        self.scopelist.pack(fill="both", expand=True, pady=(8, 0))

    def _tab_sessions(self) -> None:
        outer = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(outer, text="会话与报告")
        row = ttk.Frame(outer)
        row.pack(fill="x")
        for text, command in (
            ("刷新", self.refresh_sessions),
            ("打开目录", self.open_workspace),
            ("查看发现", self.show_selected_session),
            ("生成报告", self.report),
        ):
            ttk.Button(row, text=text, command=command).pack(side="left", padx=(0, 6))
        self.sessions = ttk.Treeview(
            outer, columns=("target", "kind", "findings", "stages", "workspace"),
            show="headings", height=14,
        )
        for column, text, width in (
            ("target", "目标", 220), ("kind", "类型", 90), ("findings", "发现", 70),
            ("stages", "阶段", 200), ("workspace", "目录", 420),
        ):
            self.sessions.heading(column, text=text)
            self.sessions.column(column, width=width, anchor="w")
        self.sessions.pack(fill="both", expand=True, pady=(8, 0))
        self.sessions.bind("<<TreeviewSelect>>", self._select_session)

    # ---- small shared helpers ---------------------------------------------
    def log(self, text: str) -> None:
        self.logbox.configure(state="normal")
        self.logbox.insert("end", text.rstrip() + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")
        print(text, file=sys.stderr)

    def status(self, text: str) -> None:
        self.status_var.set(text)

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        state = widget.cget("state")
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state=state)

    def clipboard(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except tk.TclError:  # no clipboard on a bare X session
            pass

    def _reveal(self, path: Path) -> None:
        try:
            os.startfile(str(path))  # noqa: S606 - opening Explorer is the point
        except (AttributeError, OSError):
            webbrowser.open(Path(path).as_uri())

    def _max_functions(self) -> int:
        try:
            return max(1, int(self.maxfun.get().strip() or "40"))
        except ValueError:
            return 40

    # ---- worker plumbing ---------------------------------------------------
    def _submit(self, label: str, work, done) -> None:
        """Run *work* in a thread; call *done(payload)* on the UI thread."""
        if self.busy:
            messagebox.showinfo(APP_NAME, "上一个任务还在跑，等它结束再点。")
            return
        self.busy = True
        self.status(f"{label} …（大目标可能要几分钟，界面不会卡住）")

        def runner() -> None:
            try:
                payload = work()
            except Exception as exc:  # noqa: BLE001 - shown in the window instead
                self.jobs.put(("error", label, exc, traceback.format_exc(), done))
            else:
                self.jobs.put(("done", label, payload, "", done))

        threading.Thread(target=runner, name=f"revlab-{label}", daemon=True).start()

    def _poll(self) -> None:
        while True:
            try:
                kind, label, payload, detail, done = self.jobs.get_nowait()
            except queue.Empty:
                break
            self.busy = False
            if kind == "done":
                self.status(f"{label} 完成")
                try:
                    done(payload)
                except Exception as exc:  # noqa: BLE001 - never kill the loop
                    self._failed(label, exc, traceback.format_exc())
            else:
                self._failed(label, payload, detail)
        self.root.after(120, self._poll)

    def _failed(self, label: str, exc: BaseException, detail: str) -> None:
        self.status(f"{label} 失败：{exc}")
        self.log(f"[{label}] 失败：{type(exc).__name__}: {exc}")
        self.log(detail)
        if isinstance(exc, ScopeError):
            # The gate doing its job is not a crash: it is a decision the operator
            # has to make, so put the decision one click away instead of asking
            # them to find the right tab and retype the target.
            self.offer_scope_fix()
            messagebox.showwarning(
                APP_NAME,
                f"{label} 被授权门禁拒绝：\n\n{exc}\n\n"
                "已在“授权范围”页填好目标名：点“添加”，再点“保存到配置”。",
            )
            return
        messagebox.showerror(
            APP_NAME, f"{label} 失败：\n\n{exc}\n\n完整堆栈见日志：\n{self.log_file}"
        )

    def offer_scope_fix(self) -> None:
        """Prefill the authorisation list with the current target's file name.

        Default-deny is the point of the gate, so the app never authorises
        anything by itself -- but it can save the operator from retyping a name it
        already has.
        """
        self.notebook.select(2)                     # the 授权范围 tab
        raw = self.target.get().strip()
        if not raw:
            return
        name = Path(raw).name
        existing = list(self.scopelist.get(0, "end"))
        if name and name not in existing:
            self.scope_entry.set(name)
        self.status("把目标加入授权名单后即可重试：添加 → 保存到配置")

    # ---- the buttons -------------------------------------------------------
    def _update_kind(self) -> None:
        raw = self.target.get().strip()
        if not raw:
            self.kind.set("（未选择目标）")
            return
        try:
            plan = plan_for(raw)
        except OSError as exc:
            self.kind.set(f"无法读取：{exc}")
            return
        self.kind.set(f"识别为 {plan.label} — {plan.note}")

    def pick_target(self) -> None:
        chosen = filedialog.askopenfilename(
            title="选择目标（APK / 原生库 / PE / DEX）",
            initialdir=str(app_dir()),
            filetypes=[
                ("Android / 二进制", "*.apk *.aab *.so *.dex *.exe *.dll *.bin"),
                ("APK", "*.apk"),
                ("原生库", "*.so *.dex"),
                ("全部文件", "*.*"),
            ],
        )
        if chosen:
            self.target.set(chosen)

    def make_sample(self) -> None:
        target = sample_dir() / SAMPLE_RELATIVE.name

        def work() -> Path:
            return demo.build_demo_apk(target)

        def done(path: Path) -> None:
            self.target.set(str(path))
            self.log(f"合成样本已生成: {path}")
            self.log("  内置特征：加密 DEX 体（critical）、1 MiB 高熵资源、两个 ABI 的原生库、"
                     "可调试清单、明文流量")
            self.status("样本就绪，点“开始分析”")

        self._submit("生成合成样本", work, done)

    def analyze(self) -> None:
        raw = self.target.get().strip()
        if not raw:
            messagebox.showinfo(
                APP_NAME, "先选一个目标文件；没有样本就点“生成合成样本”。"
            )
            return
        target = Path(raw)
        plan = plan_for(target)
        if plan.stage == "none":
            messagebox.showinfo(APP_NAME, f"{plan.label}\n\n{plan.note}")
            return
        config = self.config
        extract, abi = self.extract.get(), self.abi.get().strip()
        name_filter, max_functions = self.filter.get().strip(), self._max_functions()

        def work() -> dict:
            workspace, result = run_plan(
                config, plan, target, extract=extract, abi=abi,
                name_filter=name_filter, max_functions=max_functions,
            )
            return {"plan": plan, "workspace": workspace, "result": result}

        self._submit(f"分析 {plan.label}", work, self._show_result)

    def ghidra(self) -> None:
        raw = self.target.get().strip()
        if not raw:
            messagebox.showinfo(APP_NAME, "先选一个二进制文件。")
            return
        target = Path(raw)
        config = self.config
        name_filter, max_functions = self.filter.get().strip(), self._max_functions()
        plan = Plan("binary", "Ghidra 反编译", "ghidra", "导入 + 自动分析 + 反编译")

        def work() -> dict:
            session = open_session(config, str(target), kind="binary")
            result = ghidra_pass(
                config, session, str(target), name_filter=name_filter,
                max_functions=max_functions,
            )
            return {"plan": plan, "workspace": session.root, "result": result}

        self._submit("Ghidra 反编译", work, self._show_result)

    def _show_result(self, payload: dict) -> None:
        plan, workspace, result = payload["plan"], payload["workspace"], payload["result"]
        self.log(f"--- {plan.label}：{plan.note}")
        for line in summarise(result):
            self.log("  " + line)
        self.log(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        self.last_workspace = workspace
        if workspace is not None:
            self._load_findings(workspace)
        self.refresh_sessions()

    def _load_findings(self, workspace: Path) -> None:
        try:
            session = session_for(self.config, str(workspace))
        except FileNotFoundError as exc:
            self.log(str(exc))
            return
        findings = session.findings
        self.fill_findings(findings)
        target = session.summary().get("target", str(workspace))
        self.log(f"会话 {target}：发现 {len(findings)} 条 -> {workspace}")
        if findings:
            self.notebook.select(0)

    def fill_findings(self, findings) -> None:
        self.findings.delete(*self.findings.get_children())
        self.finding_detail.clear()
        for item in findings:
            severity = str(item.get("severity", "info"))
            node = self.findings.insert("", "end", tags=(severity,), values=(
                severity, item.get("title", ""), item.get("confidence", ""),
                item.get("stage", ""),
            ))
            self.finding_detail[node] = str(item.get("detail", ""))

    def _show_selected_finding(self, _event=None) -> None:
        selection = self.findings.selection()
        if not selection:
            return
        values = self.findings.item(selection[0], "values")
        self.status(f"[{values[0]}] {values[1]} · 置信度 {values[2]} · 阶段 {values[3]}")
        detail = self.finding_detail.get(selection[0], "")
        if detail:
            self.log(f"[{values[0]}] {values[1]}\n    {detail}")

    # ---- sessions, scope, reports -----------------------------------------
    def refresh_sessions(self) -> None:
        try:
            sessions = list_workspaces(self.config)
        except OSError as exc:
            self.log(f"读取会话失败: {exc}")
            return
        self.sessions.delete(*self.sessions.get_children())
        for item in sessions:
            self.sessions.insert("", "end", values=(
                item.get("target", "?"), item.get("kind", "?"),
                item.get("findings", 0), ", ".join(item.get("stages", [])),
                item.get("workspace", ""),
            ))

    def _selected_workspace(self) -> Path | None:
        selection = self.sessions.selection()
        if not selection:
            return None
        values = self.sessions.item(selection[0], "values")
        return Path(values[4]) if values and values[4] else None

    def _select_session(self, _event=None) -> None:
        workspace = self._selected_workspace()
        if workspace is not None:
            self.status(f"已选中会话 {workspace}")

    def show_selected_session(self) -> None:
        workspace = self._selected_workspace()
        if workspace is None:
            messagebox.showinfo(APP_NAME, "先在下面的表格里选一行会话。")
            return
        self.last_workspace = workspace
        self._load_findings(workspace)

    def refresh_scope(self) -> None:
        try:
            fresh = load_config(self.config_path) if self.config_path.exists() else self.config
        except ConfigError as exc:
            self.log(f"配置读取失败: {exc}")
            return
        self.config.authorised = list(fresh.authorised)
        self.scopelist.delete(0, "end")
        for item in self.config.authorised:
            self.scopelist.insert("end", item)

    def scope_add(self) -> None:
        value = self.scope_entry.get().strip()
        if not value:
            return
        self.scopelist.insert("end", value)
        self.scope_entry.set("")
        self.status("已加入列表，记得点“保存到配置”")

    def scope_remove(self) -> None:
        for index in reversed(self.scopelist.curselection()):
            self.scopelist.delete(index)

    def scope_save(self) -> None:
        values = list(self.scopelist.get(0, "end"))
        config_path = self.config_path

        def work() -> list[str]:
            return set_authorised(config_path, values)

        def done(written: list[str]) -> None:
            self.config.authorised = list(written)
            self.log(f"授权名单已写入 {config_path}（{len(written)} 项，旧文件存为 .bak）")
            self.status("授权名单已保存")

        self._submit("保存授权范围", work, done)

    def doctor(self) -> None:
        config = self.config

        def work() -> dict:
            return run_doctor(config)

        def done(payload: dict) -> None:
            self._set_text(self.doctorbox, format_doctor(payload))
            self.notebook.select(1)
            self.status("环境体检完成")

        self._submit("环境体检", work, done)

    # ---- reports and sharing ----------------------------------------------
    def _report_target(self) -> str:
        if self.last_workspace is not None:
            return str(self.last_workspace)
        selected = self._selected_workspace()
        return str(selected) if selected is not None else "latest"

    def report(self) -> None:
        config, target = self.config, self._report_target()

        def work() -> dict:
            return build_report(config, target=target, html=True)

        def done(payload: dict) -> None:
            self.written = [Path(item) for item in payload.get("written", [])]
            if payload.get("session"):
                self.last_workspace = Path(payload["session"])
            self.log("报告已写入：\n  " + "\n  ".join(str(path) for path in self.written))
            self.refresh_sessions()
            self.status("报告已生成，可点“打开报告”")

        self._submit("生成报告", work, done)

    def open_report(self) -> None:
        html = next((path for path in self.written if path.suffix == ".html"), None)
        if html is None:
            messagebox.showinfo(APP_NAME, "还没有报告：先点“生成报告”。")
            return
        self._reveal(html)

    def open_workspace(self) -> None:
        workspace = self.last_workspace or self._selected_workspace()
        if workspace is None or not workspace.exists():
            workspace = self.config.workspace_root
        self._reveal(workspace)

    def share(self) -> None:
        """Serve the browser UI on the LAN with a token, for the phone client."""
        from .webui import serve as serve_ui

        port, token = free_port(), secrets.token_urlsafe(6)
        threading.Thread(
            target=serve_ui,
            args=(self.config,),
            kwargs={"host": "0.0.0.0", "port": port, "open_browser": False,
                    "token": token},
            name="revlab-share",
            daemon=True,
        ).start()
        local = f"http://127.0.0.1:{port}/?t={token}"
        remote = f"http://{lan_address()}:{port}/?t={token}"
        self.log("界面服务已启动（本机 + 局域网，带访问码；关掉窗口即停止）：")
        self.log(f"  本机浏览器 : {local}")
        self.log(f"  手机 / 平板: {remote}")
        self.clipboard(remote)
        self.status("手机地址已复制到剪贴板，填进 Android 客户端的地址栏即可")
        webbrowser.open(local)


def main(argv: list[str] | None = None, config: Config | None = None) -> int:
    """Start the window. ``config`` arrives when the CLI already loaded one."""
    del argv  # the window takes no arguments of its own
    if getattr(sys, "frozen", False):
        # A shortcut can start the program with any working directory; relative
        # paths in the config (and the workspace) belong next to the program.
        os.chdir(app_dir())
    log_file = redirect_output()

    try:
        if config is None:
            config, config_path, notes = bootstrap_config()
        else:
            config_path = (
                Path(config.config_path) if config.config_path else default_config_path()
            )
            notes = [f"config: {config_path}"]
    except Exception as exc:  # noqa: BLE001 - there is no window to report into yet
        messagebox.showerror(APP_NAME, f"启动失败：\n\n{exc}\n\n日志：{log_file}")
        return 2

    root = tk.Tk()
    try:
        ttk.Style().configure("primary.TButton", font=("", 9, "bold"))
    except tk.TclError:  # pragma: no cover - depends on the active theme
        pass
    try:
        Window(root, config, config_path, log_file, notes)
    except Exception as exc:  # noqa: BLE001 - a broken config must not vanish
        traceback.print_exc()
        messagebox.showerror(APP_NAME, f"窗口初始化失败：\n\n{exc}\n\n日志：{log_file}")
        return 2
    root.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
