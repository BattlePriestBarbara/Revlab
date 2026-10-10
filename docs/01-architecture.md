# 01 — 架构与设计取舍

## 1. 分层

| 层 | 模块 | 职责 | 依赖 |
| --- | --- | --- | --- |
| 接口 | `cli.py` / `desktop.py` / `webui.py` / `mcp_server.py` | 四种驱动方式（命令行 / 桌面窗口 / 浏览器 / 助手），行为必須一致 | 只调用 pipeline |
| 编排 | `pipeline.py` | 四个入口：`static_triage` / `ghidra_pass` / `dynamic_pass` / `build_report` | 只调用引擎层 |
| 引擎 | `static_apk.py` / `elf.py` / `ghidra.py` / `frida_dyn.py` / `mcp_client.py` | 真正干活：解析、驱动外部工具 | 标准库 + 可选引擎 |
| 解释 | `heuristics.py` | 原始输出 → 发现（严重性 + 置信度 + 标签） | 只读引擎的数据结构 |
| 证据 | `evidence.py` | 会话目录、append-only JSONL、产物 | 标准库 |
| 样本 | `demo.py` | 结构合法的合成样本（AXML/DEX/ELF/APK），GUI 与测试共用 | 标准库 |

**为什么接口层不许有分析逻辑**：同一条规则（例如"加密 DEX 记成 critical"）如果写在 CLI 里，
Web 界面和 MCP 工具就会各写一份，然后慢慢分叉。现在三种驱动方式只是同一批函数的壳，
测试也只需要测一遍。

## 2. 证据模型：记录与发现分开

```
records.jsonl   一行一次"跑了什么"      {"ts","stage","kind","data","artifact"}
findings.jsonl  一行一条"这说明了什么"  {"id","title","severity","detail","evidence","confidence","tags"}
```

- **records** 是原始事实，追加后不再修改；
- **findings** 是解释，允许推翻重来（改了启发式，只要重跑解释，不必重跑引擎）；
- 报告由两者渲染，因此**结论永远能追到一次具体的工具运行**。

`severity ∈ {critical, high, medium, low, info}`，`confidence ∈ [0,1]`，构造时校验：
无法量化的结论不该被写进证据。

## 3. 为什么 Ghidra 走两条路

| 路线 | 何时用 | 代价 |
| --- | --- | --- |
| MCP（`ghidra.py::GhidraMcp`） | 助手问问题："这个函数做什么" × 20 次 | 需要常驻进程 + 热 JVM；首次导入仍然慢 |
| headless（`GhidraHeadless`） | 批量：导入、自动分析、跑后置脚本出 JSON | 每次都要冷启动 JVM |

`ghidra_pass(via="auto")` 先试 MCP（只做握手与能力探测），失败就落回 headless，
并把失败原因写进记录。**降级要留痕**，否则"为什么这次没结果"永远说不清。

## 4. MCP 的两副面孔

- **作为客户端**：`mcp_client.py` 直接实现 stdio JSON-RPC，不依赖 `mcp` 包。
  三个真实世界的问题必须处理：服务器往 stdout 打日志（噪声帧）、
  一次调用可能几分钟（可超时）、工具名不固定（候选名解析）。
- **作为服务器**：`mcp_server.py` 暴露 13 个工具（doctor / scope / triage / elf /
  ghidra / frida / findings / report）。助手可以完整跑完"体检 → 静态 → 动态 → 报告"，
  人只在需要授权决策时介入。

## 5. 动态层的关键约定

- **attach 默认，spawn 显式**：目标在启动 0.4 秒后自杀时，spawn 优先的工作流会白跑；
- **一个 hook 一个问题**：脚本之间不共享状态，便于单独引用某个日志段；
- **frida-server 版本必须与绑定完全一致**：不匹配时报的是"无法与远端 frida-server 通信"，
  看着像网络问题其实不是——`doctor` 会直接点出来；
- **零事件也是结论**：`hook-silent-<name>` 会写进发现，避免第二次重复试。

## 6. 已知边界

- ELF triage 不做重定位、反编译、控制流；那是 Ghidra 的活；
- 符号被 strip 的库，静态入口只能靠字符串/交叉引用，RevLab 会把这一限制写成发现
  （`all-stripped`）而不是假装成功；
- 翻译层（二进制翻译 / ARC 之类）会按构造使部分 hook 不可达：这是计划约束，不是待修的 bug。
