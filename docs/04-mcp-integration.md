# 04 — MCP 集成：两个方向都要

RevLab 在 MCP 里的角色是双向的。

## 方向一：RevLab 作为客户端（用别人的 Ghidra MCP 服务器）

`revlab/mcp_client.py` 是一个只用标准库实现的 MCP stdio 客户端。
不依赖 `mcp` 包的原因很实际：分析链路上的一个 wheel 装不上，整条链路就断了；
而 MCP 的 stdio 传输本身就是"每行一个 JSON-RPC 2.0 消息"。

它必须处理三件现实中的事：

| 问题 | 处理方式 |
| --- | --- |
| 服务器往 **stdout** 打了日志 | 非法 JSON 不抛异常，收进 `logs` 供报告引用 |
| 一次调用可能几分钟（导入大库） | 后台线程抽干 stdout，按 id 配对 + 可超时（超时报文附最后一条日志） |
| 工具名不固定 | `find_tool(*candidates)`：先精确、再忽略大小写、再子串匹配 |

测试里有两个真实子进程场景（`tests/test_mcp.py`）：噪声 stdout 与人为超时。
这两类问题用 mock 对象测不出来。

### 能力解析

`GhidraMcp.TOOL_CANDIDATES` 把"想做的事"映射到"可能是哪些工具名"：

```
list_functions   -> list_functions | get_functions | functions
decompile        -> decompile_function | decompile | get_decompiled_code
strings          -> list_strings | get_strings | search_strings | strings
...
```

`revlab ghidra tools` 会打印服务器信息、工具清单，以及**哪些能力解析成功、哪些没有**。
缺能力不是崩溃，而是降级并留痕。

## 方向二：RevLab 作为服务器（把整条链路交给助手）

```powershell
python -m revlab mcp serve        # stdio
python -m revlab mcp tools        # 查看暴露的工具
```

配置示例见 `config/cline_mcp_settings.example.json`。要点：

- `cwd` 必须是包含 `revlab.toml` 的目录，否则授权范围为空、动态工具会被门禁拒绝；
- `autoApprove` 只放只读工具（doctor/scope/sessions/findings/hooks/devices/ghidra_tools）；
  `triage`、`ghidra_summary`、`frida_run` 会改状态或耗时长，必须显式批准；
- `timeout` 给足（headless 首次导入大库可能数分钟），否则会把分析切断在中间。

### 工具清单

| 工具 | 说明 |
| --- | --- |
| `revlab_doctor` | 环境体检（含修复建议） |
| `revlab_scope` | 当前授权范围 |
| `revlab_sessions` | 工作区列表与统计 |
| `revlab_triage_apk` | 静态三连（可关解包、可指定 ABI） |
| `revlab_elf_triage` | 目录/单文件 ELF triage |
| `revlab_ghidra_tools` | Ghidra MCP 工具面与能力解析 |
| `revlab_ghidra_call` | 直接调用 Ghidra MCP 的某个工具 |
| `revlab_ghidra_summary` | headless 导入+反编译，写入证据 |
| `revlab_frida_devices` / `revlab_frida_hooks` | 设备与 hook 目录 |
| `revlab_frida_run` | 对目标跑一个 hook 并写证据 |
| `revlab_findings` | 读取按严重性排序的发现 |
| `revlab_report` | 渲染 `report.md` / `report.html` |

协议细节：`initialize` / `notifications/initialized` / `tools/list` / `tools/call` / `ping`，
返回 `result.content[0].text`（JSON 字符串）与 `isError`。工具内部异常不会杀死服务器，
而是变成 `isError: true` 的文本——助手可以看到原因并自行修正参数。

## 复合模式（两个方向同时用）

```
助手 ──MCP──▶ RevLab ──MCP──▶ Ghidra MCP 服务器（热 JVM）
                └──子进程──▶ analyzeHeadless / Frida
```

助手不需要知道 Ghidra 的 24 个工具怎么拼，只需要会用 RevLab 的 13 个高阶工具；
想深入时再用 `revlab_ghidra_call` 直接下沉。**两层协议，两种粒度。**

## 让助手产出可引用的结论

在提示里明确要求：

1. 每个结论必须引用 `findings` 里的 `id` 或 `artifacts/` 里的文件；
2. 零命中的 hook 也要写进结论（覆盖率即结论强度）；
3. `critical/high` 的发现要给出置信度与反证条件（什么观测会推翻它）。

RevLab 的证据结构就是为这几句话设计的。
