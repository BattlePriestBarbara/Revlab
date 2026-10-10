# 02 — 环境搭建

RevLab 的核心（静态 triage、报告、MCP）**零第三方依赖**，装了 Python 就能跑。
两个引擎按需安装，并且刻意装进各自的虚拟环境，避免互相打架。

## 1. 最小可用（无 Ghidra、无 Frida）

```powershell
python -m revlab doctor        # 会告诉你哪些能力可用、哪些缺失、怎么修
python scripts/make_demo_apk.py    # 合成样本：加密 DEX + 高熵资产 + 两个 .so（不碰任何第三方应用）
python -m revlab triage samples/demo.apk
python -m revlab report --target latest
python -m revlab ui            # 本地界面
python -m revlab gui           # 桌面窗口（tkinter，标准库）
```

## 1.5 打包（可选，想双击就用時）

构建桌面程序需要 python.org 的 CPython 与 PyInstaller；构建 Android 客户端需要
JDK 11+ 与带 cmdline-tools 的 Android SDK。两者都不影响"运行 RevLab"这件事：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -Shortcut
python android\build_apk.py
```

细节（产物结构、验证方式、已知坑）见 `07-packaging.md`。构建完想知道产物能不能
双击起来：`python scripts\gui_smoke_frozen.py`（把 `dist\RevLab\` 拷到 `%TEMP%`
启动，然后问 Windows 那个窗口在不在）。

## 2. Frida 侧

```powershell
python -m venv D:\frida\.venv
D:\frida\.venv\Scripts\python.exe -m pip install -r requirements-frida.txt
```

要点：

- **绑定版本 == frida-server 版本**（本项目对 17.18.0 验证）。版本不一致会报
  `unable to communicate with remote frida-server`，看起来像网络故障，其实不是；
- frida-server 以 `.xz` 发布，Windows 没有自带 xz 工具，用 Python 的 `lzma` 解：
  解到 `<frida_root>/server/frida-server-<version>-android-<arch>`；
- 设备侧需要 root。`revlab dynamic server start --abi x86_64` 会自动 push、
  `chmod 755`、启动，并在版本不匹配时**拒绝启动**并说明原因。

adbd 的坑：同一台模拟器可能同时作为传输序列号和 `host:port` 别名出现，
于是 `adb wait-for-device` 报 `more than one device/emulator`。
在 `revlab.toml` 里固定 `[frida] serial`，所有 adb 调用都会带上 `-s`。

## 3. Ghidra 侧

| 组件 | 建议版本 | 说明 |
| --- | --- | --- |
| Ghidra | 12.1.3 PUBLIC | 静态分析、反编译、项目库 |
| JDK | **21 或更高** | Ghidra 12 拒绝 JDK 8/16；机器默认往往太旧 |
| PyGhidra + jpype | 3.1.0 / 1.5.2 | MCP 服务器在进程内开 JVM，避免每次冷启动 |

```powershell
python -m venv D:\ghidra-mcp\.venv
D:\ghidra-mcp\.venv\Scripts\python.exe -m pip install -r requirements-ghidra.txt
# 离线路线：用 Ghidra 自带的 wheel
# <GHIDRA_INSTALL>\Features\PyGhidra\pypkg\dist
```

`revlab.toml` 里的 `[paths] jdk_home` 就是给 Ghidra 用的 `JAVA_HOME`：
RevLab 会把它注入 MCP 服务器进程和 `analyzeHeadless` 的环境变量，
所以机器默认 JDK 太旧也没关系，只要给对路径。

## 4. 路径必须 ASCII

PyGhidra 与 JVM 在非 ASCII 路径下启动会失败或行为异常。
本仓库（`D:\RevLab`）、Ghidra 安装目录、MCP 服务器 checkout、虚拟环境
都放在纯 ASCII 路径下。虚拟环境内嵌绝对解释器路径，换机请重建而不是拷贝。

## 5. 配置项

```toml
[paths]
ghidra_install  = "D:\\ghidra_12.1.3_PUBLIC"   # 含 support/analyzeHeadless.bat
ghidra_mcp_root = "D:\\ghidra-mcp"             # 含 server.py
frida_root      = "D:\\frida"                  # 内含 .venv/ 与 platform-tools/
jdk_home        = "C:\\Java\\jdk-21"            # 只给 Ghidra 用
android_sdk     = ""                            # platform-tools 在 frida_root 里可留空

[scope]
authorised = ["com.example.demo", "demo.apk"]   # 空 = 动态能力全部拒绝
```

同样支持环境变量：`REVLAB_GHIDRA_INSTALL`、`REVLAB_GHIDRA_MCP_ROOT`、
`REVLAB_FRIDA_ROOT`、`REVLAB_JAVA_HOME`、`REVLAB_ANDROID_SDK`。

## 6. `doctor` 会替你检查什么

| 检查 | 失败时的典型原因 |
| --- | --- |
| python / config file / workspace | 版本过低、没复制 `revlab.toml.example` |
| ghidra install / MCP server / MCP venv | 路径写错、venv 没装 PyGhidra |
| jdk for ghidra | `JAVA_HOME` 指向 1.8 或 16 |
| frida venv / binding / server binaries | 没建 venv、没解 `.xz` |
| **frida version match** | 绑定与 server 不一致（最常见、最容易被误诊） |
| adb / attached devices | platform-tools 不在路径、设备没授权调试 |
| hook catalogue / authorisation scope | 包损坏、没写授权目标 |

错误的检查项会阻塞对应阶段，警告项只降低覆盖率。
