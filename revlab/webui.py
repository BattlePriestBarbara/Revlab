"""Local web UI: the same passes, in a browser, with no framework.

Standard library only (``http.server``), bound to 127.0.0.1 by default. The page
is one HTML document with a little fetch() JavaScript; it calls exactly the same
:mod:`revlab.pipeline` functions the CLI calls, so the two cannot disagree.

Endpoints
---------
``GET  /``                 dashboard
``GET  /api/status``       toolchain + scope + counts
``GET  /api/sessions``     workspaces
``GET  /api/session``      one session (summary + findings + records)
``GET  /api/findings``     findings only
``GET  /api/hooks``        hook catalogue
``GET  /api/report``       rendered report (markdown or html)
``POST /api/triage``       static triage of an APK
``POST /api/dynamic``      one hook against one target
``POST /api/ghidra``       Ghidra pass over one binary
``POST /api/report``       write report files
"""

from __future__ import annotations

import hmac
import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .config import Config, ScopeError
from .pipeline import (
    build_report,
    dynamic_pass,
    ghidra_pass,
    list_workspaces,
    open_session,
    session_for,
    static_triage,
)
from .report import render_html, render_markdown


class Api(BaseHTTPRequestHandler):
    """Request handler; ``config`` is injected by :func:`serve`."""

    config: Config
    #: Shared secret required when the server is reachable beyond loopback.
    token: str | None = None
    server_version = "RevLab/0.1"

    # ---- helpers -----------------------------------------------------------
    def _allowed(self, query: dict) -> bool:
        """Token gate. No token configured = the loopback-only case."""
        token = type(self).token
        if not token:
            return True
        supplied = (query.get("t") or [""])[0] or self.headers.get("X-RevLab-Token", "")
        return hmac.compare_digest(supplied, token)

    def _unauthorised(self):
        return self._json(
            {
                "error": "unauthorised",
                "hint": "open the UI with ?t=<token>, or send an X-RevLab-Token header",
            },
            401,
        )

    def _page(self) -> str:
        """The dashboard, with the token handed to the page's fetch() calls."""
        script = f"<script>window.REVLAB_TOKEN={json.dumps(type(self).token)};</script>"
        return PAGE.replace("<h1>RevLab</h1>", script + "<h1>RevLab</h1>", 1)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, status: int = 200) -> None:
        self._send(
            status,
            json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _text(self, text: str, content_type: str = "text/plain; charset=utf-8",
              status: int = 200) -> None:
        self._send(status, text.encode("utf-8"), content_type)

    def log_message(self, fmt: str, *args) -> None:  # quieter, but still visible
        # Drop the query string: a token can live in it (`?t=...`), and log
        # files are exactly where secrets end up leaking from.
        safe = tuple(str(arg).split("?", 1)[0] for arg in args)
        sys.stderr.write(f"[revlab-ui] {self.address_string()} {fmt % safe}\n")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _session(self, target: str):
        target = target or "latest"
        if target != "latest":
            try:
                return session_for(self.config, target)
            except FileNotFoundError:
                return open_session(self.config, target, kind="manual")
        return session_for(self.config, "latest")

    # ---- routes ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        route = parsed.path
        if not self._allowed(query):
            return self._unauthorised()

        try:
            if route in ("/", "/index.html"):
                return self._text(self._page(), "text/html; charset=utf-8")

            if route == "/api/status":
                from .doctor import run_doctor

                sessions = list_workspaces(self.config)
                report = run_doctor(self.config)
                return self._json(
                    {
                        "toolchain": report["toolchain"],
                        "ready": report["ok"],
                        "problems": [item for item in report["checks"] if not item["ok"]],
                        "authorised": self.config.authorised,
                        "workspace": str(self.config.workspace_root),
                        "sessions": len(sessions),
                        "findings": sum(item["findings"] for item in sessions),
                    }
                )

            if route == "/api/sessions":
                return self._json({"sessions": list_workspaces(self.config)})

            if route == "/api/hooks":
                from .frida_dyn import list_hooks

                return self._json(
                    {
                        "hooks": [
                            {"name": hook.name, "summary": hook.summary, "tags": hook.tags}
                            for hook in list_hooks()
                        ]
                    }
                )

            if route in ("/api/session", "/api/findings"):
                session = self._session(query.get("target", ["latest"])[0])
                payload = session.summary()
                payload["findings"] = session.findings
                if route == "/api/session":
                    payload["records"] = session.records
                return self._json(payload)

            if route == "/api/report":
                session = self._session(query.get("target", ["latest"])[0])
                fmt = query.get("format", ["md"])[0].lower()
                if fmt == "html":
                    return self._text(render_html(session), "text/html; charset=utf-8")
                return self._text(render_markdown(session))
        except FileNotFoundError as exc:
            return self._json({"error": str(exc)}, 404)
        except Exception as exc:  # noqa: BLE001 - the UI must always answer
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        return self._json({"error": f"unknown route {route}"}, 404)

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        route = urlparse(self.path).path
        if not self._allowed(parse_qs(urlparse(self.path).query)):
            return self._unauthorised()
        payload = self._body()
        try:
            if route == "/api/triage":
                apk = str(payload.get("apk", "")).strip()
                if not apk:
                    return self._json({"error": "apk is required"}, 400)
                return self._json(
                    static_triage(
                        self.config,
                        apk,
                        extract=bool(payload.get("extract", True)),
                        abi_preference=str(payload.get("abi", "")),
                    )
                )

            if route == "/api/dynamic":
                target = str(payload.get("target", "")).strip()
                if not target:
                    return self._json({"error": "target is required"}, 400)
                session = self._session(str(payload.get("session", "latest")))
                if str(session.target) != target:
                    session = open_session(self.config, target, kind="dynamic")
                return self._json(
                    dynamic_pass(
                        self.config,
                        session,
                        target,
                        str(payload.get("hook", "api_probe")),
                        seconds=float(payload.get("seconds", 30)),
                        mode=str(payload.get("mode", "attach")),
                    )
                )

            if route == "/api/ghidra":
                binary = str(payload.get("binary", "")).strip()
                if not binary:
                    return self._json({"error": "binary is required"}, 400)
                session = self._session(str(payload.get("session", "latest")))
                return self._json(
                    ghidra_pass(
                        self.config,
                        session,
                        binary,
                        name_filter=str(payload.get("filter", "")),
                        max_functions=int(payload.get("max_functions", 40)),
                        via=str(payload.get("via", "auto")),
                    )
                )

            if route == "/api/report":
                session = self._session(str(payload.get("target", "latest")))
                return self._json(build_report(self.config, session))
        except ScopeError as exc:
            return self._json({"error": f"refused by the authorisation gate: {exc}"}, 403)
        except FileNotFoundError as exc:
            return self._json({"error": str(exc)}, 404)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        return self._json({"error": f"unknown route {route}"}, 404)


PAGE = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>RevLab — 逆向工程工作台</title>
<style>
:root { color-scheme: light dark; }
body { font-family: "Segoe UI", system-ui, sans-serif; margin: 0; padding: 1.5rem 2rem;
       max-width: 70rem; line-height: 1.55; }
h1 { font-size: 1.4rem; margin: 0 0 .2rem; }
h2 { font-size: 1.05rem; margin: 1.6rem 0 .5rem; border-bottom: 1px solid #8884; padding-bottom: .2rem; }
.row { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; margin: .4rem 0; }
input, select, button { font: inherit; padding: .35rem .5rem; border: 1px solid #8886;
       border-radius: 6px; background: transparent; color: inherit; }
button { cursor: pointer; }
button.primary { border-color: #2e7d32; color: #2e7d32; font-weight: 600; }
pre { background: #8881; padding: .6rem .8rem; border-radius: 6px; overflow: auto; max-height: 22rem;
      font-size: .84rem; }
.pill { display: inline-block; padding: .1rem .55rem; border-radius: 999px; font-size: .8rem;
        border: 1px solid #8886; }
.pill.ok { color: #2e7d32; border-color: #2e7d32; }
.pill.bad { color: #b00020; border-color: #b00020; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { border: 1px solid #8884; padding: .3rem .5rem; text-align: left; }
.finding { border-left: 4px solid #999; padding: .5rem .7rem; margin: .5rem 0; background: #8881; }
.critical { border-color: #b00020; } .high { border-color: #d84315; }
.medium { border-color: #f9a825; } .low { border-color: #2e7d32; } .info { border-color: #607d8b; }
.small { font-size: .85rem; color: #777; }
</style></head><body>
<h1>RevLab</h1>
<p class="small">Ghidra + Frida + MCP 的逆向工程工作台。所有动作都会写进会话证据目录，
报告可重新生成；动态能力只对 <code>[scope] authorised</code> 中的目标生效。</p>
<p><span id="status" class="pill">检查中…</span> <span id="scope" class="small"></span></p>
<div id="problems" class="small"></div>

<h2>1. APK 静态三连（清单 / 熵 / ELF）</h2>
<div class="row">
  <input id="apk" size="52" placeholder="C:\\samples\\demo.apk">
  <input id="abi" size="8" placeholder="ABI" value="x86_64">
  <label class="small"><input type="checkbox" id="extract" checked> 解包原生库与 DEX</label>
  <button class="primary" onclick="triage()">开始 triage</button>
</div>
<pre id="triageOut">—</pre>

<h2>2. 动态观测（一个 hook 回答一个问题）</h2>
<div class="row">
  <input id="appTarget" size="26" placeholder="包名或 pid">
  <select id="hook"></select>
  <input id="seconds" size="4" value="30">
  <select id="mode"><option>attach</option><option>spawn</option></select>
  <button class="primary" onclick="runHook()">运行 hook</button>
</div>
<pre id="hookOut">—</pre>

<h2>3. Ghidra（MCP 优先，headless 兜底）</h2>
<div class="row">
  <input id="binary" size="52" placeholder="...artifacts\\native\\lib\\x86_64\\libfoo.so">
  <input id="filter" size="16" placeholder="函数名过滤（可空）">
  <button onclick="ghidra()">导入并反编译</button>
</div>
<pre id="ghidraOut">—</pre>

<h2>4. 会话与发现</h2>
<div class="row"><button onclick="loadSessions()">刷新会话</button>
  <button onclick="writeReport()">生成报告</button>
  <a class="small" href="#" onclick="openReport(event)">打开报告(HTML)</a>
  <span id="reportOut" class="small"></span></div>
<table id="sessions"><tr><th>目标</th><th>类型</th><th>发现</th><th>阶段</th><th>目录</th></tr></table>
<div id="findings"></div>

<script>
const $ = (id) => document.getElementById(id);
async function post(url, body) {
  const r = await fetch(withToken(url), {method: 'POST', headers: {'Content-Type': 'application/json'},
                              body: JSON.stringify(body)});
  return await r.json();
}
async function get(url) { return await (await fetch(withToken(url))).json(); }
function withToken(url) {
  if (!window.REVLAB_TOKEN) return url;
  return url + (url.indexOf('?') >= 0 ? '&' : '?') + 't=' + encodeURIComponent(window.REVLAB_TOKEN);
}
function openReport(ev) {
  if (ev) ev.preventDefault();
  window.open(withToken('/api/report?format=html&target=latest'), '_blank');
}
function show(id, payload) { $(id).textContent = JSON.stringify(payload, null, 2); }

async function status() {
  const s = await get('/api/status');
  const pill = $('status');
  pill.textContent = s.ready ? '环境就绪' : '存在阻塞项';
  pill.className = 'pill ' + (s.ready ? 'ok' : 'bad');
  $('scope').textContent = '授权范围: ' + (s.authorised.join(', ') || '(未配置)') +
      ' · 工作区: ' + s.workspace + ' · 会话 ' + s.sessions + ' · 发现 ' + s.findings;
  $('problems').innerHTML = s.problems.map(p => '<div>• ' + p.name + ': ' + p.detail +
      (p.hint ? ' <em>→ ' + p.hint + '</em>' : '') + '</div>').join('');
}

async function triage() {
  const apk = $('apk').value.trim();
  if (!apk) return;
  $('triageOut').textContent = '分析中（首次会解包并 triage 原生库，可能需要一会儿）…';
  show('triageOut', await post('/api/triage',
      {apk: apk, abi: $('abi').value.trim(), extract: $('extract').checked}));
  loadSessions();
}

async function hooks() {
  const data = await get('/api/hooks');
  $('hook').innerHTML = data.hooks.map(h => '<option value="' + h.name + '" title="' +
      h.summary + '">' + h.name + '</option>').join('');
}

async function runHook() {
  const target = $('appTarget').value.trim();
  if (!target) return;
  $('hookOut').textContent = '观测中…';
  show('hookOut', await post('/api/dynamic', {target: target, hook: $('hook').value,
      seconds: parseInt($('seconds').value || '30', 10), mode: $('mode').value}));
  loadSessions();
}

async function ghidra() {
  const binary = $('binary').value.trim();
  if (!binary) return;
  $('ghidraOut').textContent = 'Ghidra 分析中（headless 首次导入可能数分钟）…';
  show('ghidraOut', await post('/api/ghidra', {binary: binary, filter: $('filter').value.trim()}));
}

async function loadSessions() {
  const data = await get('/api/sessions');
  const rows = data.sessions.map(function (s) {
    const key = encodeURIComponent(s.workspace);
    return '<tr><td><button onclick="loadFindings(decodeURIComponent(\\'' + key +
        '\\'))">' + s.target + '</button></td><td>' + s.kind + '</td><td>' + s.findings +
        '</td><td>' + s.stages.join(', ') + '</td><td class="small">' + s.workspace + '</td></tr>';
  });
  $('sessions').innerHTML =
      '<tr><th>目标</th><th>类型</th><th>发现</th><th>阶段</th><th>目录</th></tr>' + rows.join('');
}

async function loadFindings(workspace) {
  const data = await get('/api/session?target=' + encodeURIComponent(workspace));
  const blocks = data.findings.map(function (f) {
    return '<div class="finding ' + f.severity + '"><b>' + f.title + '</b> <span class="small">' +
        f.severity + ' · 置信度 ' + f.confidence + ' · ' + f.stage + '</span><div class="small">' +
        (f.detail || '') + '</div></div>';
  });
  $('findings').innerHTML = '<h3 class="small">' + data.target + '（发现 ' +
      data.findings.length + ' 条）</h3>' + blocks.join('');
}

async function writeReport() {
  const result = await post('/api/report', {target: 'latest'});
  $('reportOut').textContent = result.error ? result.error : '已写入: ' + result.written.join(' ');
  loadSessions();
}

status(); hooks(); loadSessions();
</script>
</body></html>
"""


def serve(config: Config, host: str = "127.0.0.1", port: int = 8765,
          open_browser: bool = True, token: str | None = None) -> int:
    """Serve the dashboard until Ctrl+C.

    Anything other than loopback is a network service, and this one can start
    dynamic instrumentation, so binding a real interface without a token is
    refused rather than merely warned about.
    """
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        print(
            f"refusing to bind {host} without a token: this UI can start dynamic "
            "instrumentation\n"
            "  hint: --token auto   (a code is generated and printed)",
            file=sys.stderr,
        )
        return 2
    handler = type("BoundApi", (Api,), {"config": config, "token": token})
    httpd = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/"
    print(f"RevLab UI on {url}{'?t=' + token if token else ''} "
          f"(workspace: {config.workspace_root})")
    if open_browser:
        try:
            webbrowser.open(f"{url}?t={token}" if token else url)
        except Exception:  # noqa: BLE001 - headless machines have no browser
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.server_close()
    return 0
