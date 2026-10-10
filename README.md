# RevLab — AI/MCP 驱动的逆向工程工作台

RevLab 把 **Ghidra（静态）** 与 **Frida（动态）** 收进同一个协议化的界面后面，
用 **MCP** 把两家都变成可被助手调用的"工具"，并把每一次观测都写成 JSON 证据。
它既是一个能用的工具，也是一个可以照着抄的架构：

```
                 ┌──────────────────────────────────────────────┐
   人 / 助手 ───▶ │  CLI  revlab ...   ·   本地 Web UI  ·  MCP 服务器 │
                 └───────────────┬──────────────────────────────┘
                                 ▼
                 ┌──────────────────────────────────────────────┐
                 │  pipeline：triage → Ghidra → Frida → 报告      │
                 └───┬──────────────────┬───────────────────┬───┘
         MCP (stdio) │          子进程    │           子进程   │
                     ▼                  ▼                   ▼
        ┌────────────────────┐ ┌──────────────────┐ ┌────────────────────┐
        │ Ghidra MCP 服务器   │ │ analyzeHeadless  │ │ Frida + adb        │
        │ （常驻热 JVM）      │ │ （批量导入/分析） │ │ frida-server/设备  │
        └────────────────────┘ └──────────────────┘ └────────────────────┘
                                 ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ 会话目录：session.json · records.jsonl · findings.jsonl ·     │
        │ artifacts/ · report.md · report.html                          │
        └──────────────────────────────────────────────────────────────┘
```

## 它解决什么问题

逆向分析真正难的不是"跑一个工具"，而是**记不住、说不清、复现不了**。RevLab 的取舍是：

1. **先分级再花钱**。APK 的第一次扫描不依赖 Ghidra/Frida，只用标准库：解析二进制清单、
   算 ZIP/DEX 熵、判断 DEX 是真代码还是加密载荷、对原生库做 ELF triage。
   几十秒内决定"值不值得反编译"，而不是一上来就开 Ghidra。
2. **证据即数据**。所有阶段的输出都是 JSON（`records.jsonl` 记录了"跑了什么"，
   `findings.jsonl` 记录了"这说明了什么"，带严重性与置信度）。报告可重新生成，
   结论可追溯。
3. **一个 hook 回答一个问题**。内置 4 个 Frida 脚本，每个只做一件事；
   "hook 了但一次都没触发"也会被写成结论——它排除掉了一整类保护方式。
4. **协议优先**。Ghidra 通过 MCP 问（热 JVM，问二十次也不贵），
   RevLab 自己也是 MCP 服务器，所以助手可以直接驱动整条链路。
5. **默认拒绝**。动态能力只对 `revlab.toml` 里 `[scope] authorised` 写下的目标生效；
   没写就什么都不做——这是默认值，不是可选项。

## 快速开始

### 想直接双击用？先构建桌面程序

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -Shortcut
# 产物：dist\RevLab\RevLab.exe（双击即用，无需命令行）
#       dist\RevLab\RevLabCLI.exe（同样的命令，供脚本/CI）
```

首次双击会在 exe 同级写出 `revlab.toml`、`workspaces\`、`samples\`；
窗口日志在 `%LOCALAPPDATA%\RevLab\logs\revlab-desktop.log`。
想要手机端（第二个屏幕）就再构建 `dist\RevLab-Mobile-0.2.0.apk`：

```powershell
python android\build_apk.py
```

两条链路的细节、产物结构、以及踩过的坑都在 [docs/07-packaging.md](docs/07-packaging.md)。

### 命令行方式

```powershell
# 0) 依赖：核心零依赖；两个引擎按需装（各用各的虚拟环境）
python -m pip install -r requirements-frida.txt      # Frida 侧
python -m pip install -r requirements-ghidra.txt     # Ghidra 侧（或装 Ghidra 自带 wheel）

# 1) 配置：填机器路径 + 写下你被授权分析的目标
copy revlab.toml.example revlab.toml
notepad revlab.toml

# 2) 环境体检（每一条都会给出修复建议）
python -m revlab doctor

# 3) 静态三连：清单 + 熵 + ELF，产物落在 workspaces/<target>-<hash>/
#    没有样本？先造一个合成 APK（加密 DEX + 高熵资产 + 两个 .so）：
python scripts/make_demo_apk.py
python -m revlab triage samples/demo.apk
python -m revlab triage C:\samples\your-own.apk

# 4) Ghidra：列出 MCP 工具 / 直接调用 / 批量反编译
python -m revlab ghidra tools
python -m revlab ghidra call decompile_function --args "{\"function_name\": \"JNI_OnLoad\"}"
python -m revlab ghidra summary workspaces\...\artifacts\native\lib\x86_64\libfoo.so --filter crypt

# 5) 动态：设备与 frida-server，然后一次一个 hook
python -m revlab dynamic devices
python -m revlab dynamic server start --abi x86_64
python -m revlab dynamic hooks
python -m revlab dynamic run com.example.demo --hook dex_watch --seconds 60

# 6) 报告 + 界面（窗口 / 浏览器 / 手机三选一）
python -m revlab report --target latest
python -m revlab gui                 # 桌面窗口（tkinter，零依赖）
python -m revlab ui                  # http://127.0.0.1:8765
python -m revlab ui --host 0.0.0.0 --token auto   # 给手机用（非回环必须带访问码）
```

## 命令一览

| 命令 | 作用 |
| --- | --- |
| `revlab doctor` | 工具链体检：Ghidra/JDK≥21/Frida 版本匹配/adb/设备/hook/授权范围 |
| `revlab scope` | 打印当前授权范围（动态能力的门禁） |
| `revlab triage <apk>` | 静态三连：AXML 清单、ZIP+DEX 熵分析、原生库 ELF triage（并解包待分析文件）|
| `revlab elf <path>` | 单独对目录/文件做 ELF triage |
| `revlab ghidra tools\|call\|summary` | 查看 MCP 工具面 / 直接调用 / headless 导入+反编译 |
| `revlab dynamic devices\|ps\|hooks\|server\|run` | 设备、进程、hook 目录、frida-server 生命周期、运行 hook |
| `revlab sessions` | 列出所有工作区与发现统计 |
| `revlab report` | 生成 `report.md` / `report.html` |
| `revlab mcp serve` | 把 RevLab 本体作为 MCP 服务器暴露给助手（stdio） |
| `revlab gui` | 桌面窗口：选目标→分析→发现表格→报告→改授权，全在窗口里 |
| `revlab ui` | 零依赖本地 Web 界面（默认只监听 127.0.0.1；非回环必须 `--token`） |

所有命令都支持 `--json`，便于接进别的流水线。

## 目录结构

```
revlab/
  config.py        配置载入 + 授权门禁（[scope] authorised）
  evidence.py      Session / Finding：append-only 证据与解释
  doctor.py        环境体检（每项都带修复建议）
  static_apk.py    AXML 解析、ZIP/DEX 清单与熵、安全解包
  elf.py           零依赖 ELF triage（头/节/DT_NEEDED/符号/JNI 入口/横幅）
  heuristics.py    启发式规则：证据 → 严重性 + 置信度 + 下一步
  ghidra.py        Ghidra MCP 客户端封装 + analyzeHeadless 批处理
  ghidra_scripts/  ExportProgramSummary.java（headless 后置脚本 → JSON）
  mcp_client.py    零依赖 MCP stdio 客户端（超时/噪声/多帧都处理）
  mcp_server.py    RevLab 作为 MCP 服务器（13 个工具）
  frida_dyn.py     设备/frida-server 生命周期、hook 目录、事件采集
  hooks/           4 个 Frida 脚本（api_probe / anti_debug_probe / jni_boundary / dex_watch）
  pipeline.py      triage / ghidra / dynamic / report 四个入口
  report.py        Markdown + 自包含 HTML 报告
  demo.py          合成样本构建器（结构合法的 AXML/DEX/ELF/APK，GUI 的"生成样本"用它）
  desktop.py       桌面窗口（tkinter 薄壳，工作线程 + 队列，首次运行写配置、日志落盘）
  cli.py           命令行
  webui.py         本地 Web 界面（http.server，无框架；非回环强制访问码）
scripts/
  make_demo_apk.py 合成样本生成器（加密 DEX + 高熵资产 + 两个 .so，无需第三方应用）
  make_icon.py     纯标准库画图标（.ico + Android mipmap PNG，不引 Pillow）
  build_exe.ps1    构建 RevLab.exe / RevLabCLI.exe 并验证窗口真的出现
  gui_smoke.py     无头冒烟：真建窗口、真点按钮（样本→分析→报告→体检→改授权）
  gui_smoke_frozen.py  冻结版冒烟：拷到 %TEMP% 跑，再问 Windows 那个窗口在不在
packaging/
  revlab.spec      PyInstaller 配方（两个 exe 共用一次分析）
  entry_gui.py     入口：revlab.desktop:main
  entry_cli.py     入口：revlab.cli:main
  revlab.ico       图标（生成物）
android/
  build_apk.py     免 Gradle 构建手机客户端（aapt2 + javac + d8 + zipalign + apksigner）
  check_toolchain.py  dex 步骤能力自检（含本机 R8 对 InnerClasses 的已知崩溃）
  java/ ...        两个顶层类：MainActivity（WebView + 地址栏）、ConnectListener
  AndroidManifest.xml
docs/              架构、环境、工作流、MCP 集成、范围、路线图、打包
tests/             137 个标准库 unittest（合成 APK/ELF/AXML，不需要真机）
```

## 质量门

```powershell
python -m unittest discover -s tests -t .     # 137 tests，全部离线运行
python -m py_compile revlab\*.py              # 语法门
node --check revlab\hooks\*.js                # hook 语法门
python scripts\gui_smoke.py                   # 桌面窗口冒烟（真建窗口、真点按钮）
python scripts\gui_smoke_frozen.py            # 冻结版冒烟（拷到 %TEMP%，找那个真窗口；需先构建）
python android\check_toolchain.py             # 手机端 dex 步骤能力自检
```

## 范围与合规

只对你拥有或明确获得授权测试的软件使用本工具。动态分析能力（设备 hook）默认全部关闭，
直到你把目标写进 `[scope] authorised`。详见
[`docs/05-scope-and-limits.md`](docs/05-scope-and-limits.md)。

## License

MIT —— 全文见 [`LICENSE`](LICENSE)。

Copyright (c) 2026 **Xinhang Yu**

这一条不是免责声明里的套话：动态能力默认全部关闭，只对 `[scope] authorised` 里
写下的目标生效（见 [`docs/05-scope-and-limits.md`](docs/05-scope-and-limits.md)）。

