# 07 — 打包与分发：双击即用的 .exe 与 Android .apk

RevLab 本体只依赖 Python 标准库，所以"运行"从来不是问题；"**点开就能用**"才是。
本章记录两件产物、它们的构建方式、以及构建过程中真正踩到的坑。

| 产物 | 路径 | 用途 |
| --- | --- | --- |
| 桌面程序 | `dist\RevLab\RevLab.exe` | 双击打开窗口，无需命令行 |
| 命令行版 | `dist\RevLab\RevLabCLI.exe` | 同样的命令，供脚本 / CI / 助手调用 |
| 手机客户端 | `dist\RevLab-Mobile-0.2.0.apk` | 在手机上看 PC 上的工作台 |

---

## 1. 桌面版：RevLab.exe

### 1.1 产物长什么样

```
dist\RevLab\
  RevLab.exe            窗口程序（无控制台；启动时把 stdout/stderr 写进日志）
  RevLabCLI.exe         控制台程序：revlab doctor / triage / ghidra / mcp ...
  revlab.toml           首次运行时自动写出（内容 = 模板，路径留空表示自动探测）
  workspaces\           证据目录：每个目标一个 <名字>-<hash> 文件夹
  samples\              合成样本（点"生成合成样本"时写入）
  _internal\            PyInstaller 收进来的解释器、tkinter、hooks、ghidra_scripts
    _tcl_data\          Tcl 8.6 库：init.tcl、encoding\、tcl8\…（窗口能不能起来就看它）
    _tk_data\           Tk 8.6 库：tk.tcl、ttk\、images\…
```

* **日志**：`%LOCALAPPDATA%\RevLab\logs\revlab-desktop.log`。窗口程序没有控制台，
  这是唯一的真相来源；任何失败也会同时弹对话框，而不是静静死掉。
* **免安装**：整个 `dist\RevLab\` 目录拷到哪里都能跑（路径含中文也没问题——
  桌面程序从不把路径交给 `cmd.exe` 解析）。
* **onedir 与 onefile**：默认 onedir（启动快、文件可见）；`-OneFile` 额外产出
  `RevLab-Portable.exe`，单个文件但每次启动会解包到 `%TEMP%`。

### 1.2 构建

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -OneFile -Shortcut   # 再要单文件 + 桌面快捷方式
```

脚本依次做四件事，**前三件是构建，第四件是验证**：

1. 找一个 PyInstaller 支持的解释器（python.org 的 CPython 3.9+）。它会主动拒绝
   MSYS2/mingw 的 `python.exe`——那不是标准 ABI，PyInstaller 不支持；
2. 在 `packaging\.venv-build\` 里装 PyInstaller（RevLab 本体没有运行期依赖，
   所以冻结进去的只有它自己 + tkinter + hook 脚本 + Ghidra 后置脚本 + 文档）；
3. 跑 `packaging\revlab.spec`：一次分析产出两个 exe（`RevLab.exe` 无控制台，
   `RevLabCLI.exe` 有控制台），共享同一份收集结果。spec 自己先做两项检查，不通过
   就让构建失败：Tcl/Tk 库文件确实进了收集结果，并且**不是**从本项目的
   `dist\` / `build\` 里捡来的（见第 3 节最后一个坑）；
4. **验证**：`scripts\gui_smoke_frozen.py` 把整个程序拷到 `%TEMP%`、清掉继承来的
   `TCL_LIBRARY` / `TK_LIBRARY`，启动 `RevLab.exe`，然后**真的去问 Windows**：
   这个进程有没有一个可见的顶层窗口、标题里带 `RevLab`；顺带跑一次
   `RevLabCLI.exe --version`，并指出首次运行写出的 `revlab.toml`。

"构建退出码 0" 不等于 "能启动"，因此第 4 步不是可选项（`-NoSmokeTest` 可以关掉，
但没有人该关掉它）。

### 1.3 窗口里有什么

界面是薄壳：按钮只收集输入，工作线程调用 `revlab.pipeline` 的同一个函数，
和 CLI、Web UI、MCP 服务器用的是同一套代码。

| 按钮 / 区域 | 背后调用 |
| --- | --- |
| 目标 + 浏览… + 识别为… | `revlab.elf.sniff` 按**内容**判断（APK 的判据是 zip 里真有 `AndroidManifest.xml`） |
| 开始分析 | `static_triage`（APK）/ `elf_triage`（ELF）/ `ghidra_pass`（PE、DEX、Mach-O） |
| Ghidra 反编译 | `ghidra_pass`（函数过滤、最多函数数可填） |
| 生成报告 | `build_report` → `report.md` + `report.html` |
| 打开报告 / 打开产物目录 | 打开写出的文件 / 打开工作区 |
| 共享给浏览器/手机 | `webui.serve(host="0.0.0.0", token=…)`：本机浏览器 + 局域网地址（含访问码，已复制到剪贴板） |
| 生成合成样本 | `revlab.demo.build_demo_apk`（加密 DEX、高熵资产、两个 `.so`，已知结论） |
| 环境体检 | `run_doctor` / `format_doctor` |
| 授权范围 | `config.set_authorised`：就地改写 `[scope] authorised`，保留注释，旧文件存 `.bak` |
| 发现与输出 | 会话的 `findings.jsonl` 渲染成表格（严重性着色），原始 JSON 在日志页 |
| 会话与报告 | `list_workspaces` 的目录表，可查看发现 / 重新生成报告 |

长任务在工作线程里跑，结果通过队列回到主线程（`after(120, …)`），
所以界面不会卡住，控件也只在主线程被触碰。

**首次运行会先"被拒绝"一次，这是设计。** 新写出的 `revlab.toml` 里
`[scope] authorised` 是空的，而 RevLab 的默认姿态是"没写下就不动手"。
所以第一次点某个目标时，窗口会说明原因，并自动切到「授权范围」页、把目标文件名
填进输入框——点"添加"、再点"保存到配置"即可重试。
程序不会替你授权任何东西（哪怕它自己刚生成的样本）。

### 1.4 与两个引擎的关系

核心 `.exe` 里没有 frida、没有 MCP SDK、没有 jpype：静态三连、ELF triage、
报告、Web UI、桌面窗口全部可用。需要动态能力时二选一：

* 构建时 `-WithEngines`（把 `requirements-frida.txt` / `requirements-ghidra.txt` 一并冻结进去）；
* 或按 `docs/02-environment.md` 在目标机上装好，RevLab 会自己找到它们。

缺失时的报错是可读的（"需要 frida：pip install -r requirements-frida.txt"），
不是一句 traceback。

---

## 2. 手机端：RevLab-Mobile-0.2.0.apk

### 2.1 它是什么

一个 Activity、一个 WebView、一个地址栏，**不含任何分析代码**。
Ghidra 装在哪台机器上、设备插在哪台机器上，工作台就在哪台机器上——
手机做不了那件事，能做的是把同一个工作台放到第二块屏幕上：

```
PC:  RevLab.exe → 点"共享给浏览器/手机"  →  打印两个地址，并把手机地址放进剪贴板
手机: RevLab Mobile → 地址栏粘贴 http://192.168.1.5:8765/?t=<访问码> → 连接
```

`?t=` 是本次会话的访问码；没有它，服务端一律回 `401`。

### 2.2 构建（不需要 Gradle）

```powershell
python android\build_apk.py                 # 或包装脚本 android\build_apk.ps1
python android\build_apk.py --sdk C:\Android\Sdk --java-home C:\jdk-17 --skip-install
```

Gradle 会为了编译两个类而引入构建系统、插件仓库和守护进程，而真正干活的四个工具
（`aapt2`、`javac`、`d8`、`zipalign`+`apksigner`）都在 Android SDK 的
build-tools 里。所以只要求两样东西：**JDK 11+** 和 **带 cmdline-tools 的 Android SDK**。

* 缺 `build-tools` / `platforms` 时，脚本先走 `sdkmanager`（并自动接受 SDK licences），
  不行就直接从 `dl.google.com` 下载同名包（zip 内目录名不一定是 SDK 期望的名字，
  脚本会把它搬到正确位置）。
* 构建链路与校验：

  | 步骤 | 工具 | 校验点 |
  | --- | --- | --- |
  | 资源 + 清单 | `aapt2 compile` → `aapt2 link` | 生成不含代码的包 |
  | 源码 | `javac --release 11` | 只依赖 `android.jar` |
  | 字节码 | `d8`（直接起 `lib\d8.jar`，不走 `.bat`） | 产出 `classes.dex` |
  | 装包 | `zipfile` 追加 dex | 不动已有条目 |
  | 对齐 / 签名 | `zipalign -p 4` → `apksigner`（v1+v2，自签开发密钥） | `apksigner verify` 通过 |
  | 产物自检 | `aapt2 dump badging` + 读 zip | 包名 / 版本 / 有 dex / `resources.arsc` 未压缩 / 有可启动 Activity |

  最后一行是刻意保留的：`resources.arsc` 若被压缩，Android 11+ 会拒绝安装——
  "能构建" 和 "能安装" 不是一回事。

* 产物：`dist\RevLab-Mobile-0.2.0.apk`（约 25 KiB），`adb install -r` 即可。
* 密钥：首次构建生成 `android\revlab-debug.keystore`（已 gitignore）。
  它是开发密钥，不是发布身份。

### 2.3 安全边界

* 权限只要 `INTERNET`，没有别的；
* 允许明文 HTTP（`usesCleartextTraffic="true"`）是刻意的：这是局域网服务；
* 服务端只在**本机回环**上才允许不带访问码运行；绑定 `0.0.0.0` 之类的真实网卡时
  没有 `--token` 会**直接拒绝启动**（不是警告）；
* 访问码只通过 URL 参数或 `X-RevLab-Token` 头传递，并且 Web UI 的访问日志会
  把 query string 抹掉——日志文件正是密钥最容易泄漏的地方；
* 动态分析（Frida）仍然只对 `[scope] authorised` 里的目标生效；
  手机能看到界面，但看不到"授权以外"的能力。

---

## 3. 这台机器上踩到的四个坑（都能复现）

| 症状 | 根因 | 处置 |
| --- | --- | --- |
| `aapt2 W … Failed to stat file 'C:\Users\<中文用户名>\…\android.jar'`，紧接着 `d8` 抛 `NullPointerException` | PowerShell 5.1 把非 ASCII 路径（本机用户名是中文）和 `-Dname=value` 形式的参数传给原生程序时会被破坏 | 构建改用 **Python `subprocess`** 驱动（参数列表 → Windows 拿到精确的 UTF-16 命令行），并直接起 `d8.jar` / `apksigner.jar`，绕开 `.bat`。`android/build_apk.ps1` 现在只是包装 |
| `aapt2 link` 报 `AndroidManifest.xml:8: error: not well-formed (invalid token)` | XML 注释里出现了 `--`（XML 规范禁止） | 改写注释措辞 |
| `d8` 对含匿名内部类的 class 抛 `Cannot invoke "String.length()" because "<parameter1>" is null` | 本机 R8 在解析**带 `InnerClasses` 属性**的 class 文件时崩溃；与 JDK 版本（16/25）、`--release`（8/11/17）、调试信息、路径是否 ASCII 均无关，`build-tools` 29.0.3 → 36.0.0 全部复现（对照实验见下） | 客户端保持「**一文件一顶层类**」；构建脚本检测到 `$` 类名会给出明确提示；`python android\check_toolchain.py` 让工具链自己回答 |
| 双击 `RevLab.exe` 一闪而过；日志里 `_tkinter.TclError: Can't find a usable init.tcl in the following directories: …\lib\tcl8.6 …\library` | **两半各自都对，合起来却断了**：Tcl/Tk 文件确实被收集进包（构建期 `hook-_tkinter` 负责），但 spec 为了从共享分析里挑出入口脚本，把 PyInstaller 的运行期钩子 `pyi_rth__tkinter`（负责设 `TCL_LIBRARY`）一起丢掉了 | `script_for()` 现在保留所有 `pyi_rth_*`；spec 在构建期校验 Tcl/Tk 载荷与其来源；验证脚本改成"找窗口"而不是"看日志"（见下） |

第三条值得记住，因为它把一个"玄学错误"变成了可复现的判据：

```powershell
python android\check_toolchain.py
#   Plain          OK    (no library types, no nesting)
#   PlainActivity  OK    (extends an android.jar class (library resolution required))
#   Nested         FAIL  (contains an anonymous class (InnerClasses attribute))
```

也就是说：继承 `Activity`、使用 `Button`/`WebView` 都没问题，
**只要类文件本身不携带 `InnerClasses`**。因此 `ConnectListener` 是一个独立的顶层类，
而 `tests/test_packaging.py` 会阻止嵌套类悄悄回来。

### 第四个坑：Tcl/Tk —— 文件在包里，但没人给它指路

Tcl 启动时并不知道自己的库在哪：它先看环境变量 `TCL_LIBRARY`，没有就按 exe 的位置
猜一圈（`lib\tcl8.6`、`library`、`tcl8.6.15\library`），全猜不到就报：

```
_tkinter.TclError: Can't find a usable init.tcl in the following directories:
    <dist>\lib\tcl8.6 <dist>\library <dist>\tcl8.6.15\library ...
This probably means that Tcl wasn't installed properly.
```

PyInstaller 把这件事拆成两半，而且**分别落在 `Analysis` 的两个地方**：构建期
`hook-_tkinter` 把库收进 `a.datas`（产物里就是 `_internal\_tcl_data` / `_tk_data`），
运行期 `pyi_rth__tkinter` 负责设 `TCL_LIBRARY`，而运行期钩子是被塞进 `a.scripts` 的
（`build_main.py`：`self.scripts = rthook_toc + program_toc`）。

spec 里有个 `script_for()`，干的是"从一个共享分析里挑出各自的入口脚本"这件事——
它当时只返回匹配的那个入口，于是 `pyi_rth__tkinter` 被静默丢掉：**库在包里，
没人指路**。症状是"日志文件明明长了，窗口却没出来"。

排错按这个顺序走，每一步都能证伪下一步：

```powershell
# 1. 构建环境里的 Tcl/Tk 到底在哪（真起一个 Tcl 解释器问它）
python -c "import sys, tkinter; print(sys.base_prefix); print(tkinter.Tcl().eval('info library'))"
#   C:\Users\<you>\...\Python312
#   C:\Users\<you>\...\Python312\tcl\tcl8.6        <- init.tcl 就在这个目录里

# 2. 包里有没有（构建之后）
Test-Path dist\RevLab\_internal\_tcl_data\init.tcl     # 期望 True
Test-Path dist\RevLab\_internal\_tk_data\tk.tcl        # 期望 True

# 3. 是"没收集"还是"没人指路"？手动指一次就知道了
$env:TCL_LIBRARY = "$PWD\dist\RevLab\_internal\_tcl_data"
$env:TK_LIBRARY  = "$PWD\dist\RevLab\_internal\_tk_data"
.\dist\RevLab\RevLab.exe          # 这次窗口起来了 → 缺的是运行期钩子，不是数据
```

第 3 步最有用：它把"打包玄学"一刀切成"数据问题"还是"钩子问题"。

**但它有副作用，必须记住。** PyInstaller 收集 Tcl/Tk 时是真的起一个 Tcl 解释器问
`info library`，所以这两个变量一旦留在 shell 里，下一次构建就会从**上一轮的
`dist\`** 里搬库——而构建同时在写那个目录，于是 926 个文件搬不到（包括
`init.tcl`），产物却照样"构建成功"。因此现在是这样分工的：

* `scripts\build_exe.ps1` 在跑 PyInstaller 之前显式丢掉继承来的 `TCL_LIBRARY` /
  `TK_LIBRARY` / `PYTHONHOME` / `PYTHONPATH`，并打印它丢了什么；
* spec 发现库文件来自本项目自己的 `dist\` / `build\` 时**直接终止构建**，
  载荷缺失（`_tcl_data\init.tcl` 或 `_tk_data\tk.tcl`）也终止；
* `scripts\gui_smoke_frozen.py` 在子进程环境里同样清掉这些变量——否则一个"碰巧
  正确"的 shell 会让坏产物看起来是好的。

同一个道理也让验证方式换了一次：**日志增长不是证据**（日志在 `tk.Tk()` 之前就打开
了，启动失败的 traceback 也会让它增长，只是没人读）。现在断言的是窗口本身——把
`dist\RevLab\` 拷到 `%TEMP%` 启动，再用 `EnumWindows` +
`GetWindowThreadProcessId` + `IsWindowVisible` 找出属于那个 pid 的可见顶层窗口，
标题里还得有 `RevLab`。

想在终端里直接看这次崩溃：`dist\RevLab\RevLabCLI.exe gui` 走的是同一个
`desktop.main`——无控制台版把 traceback 写进日志，控制台版直接打出来。

---

## 4. 质量门

```powershell
python -m unittest discover -s tests -t .      # 137 tests，离线运行
python scripts\gui_smoke.py                    # 真建窗口、真点按钮（创建样本→分析→报告→体检→改授权）
python scripts\gui_smoke_frozen.py             # 冻结版：拷到 %TEMP% 启动，再找那个窗口（需先构建）
python android\check_toolchain.py              # dex 步骤的能力自检
powershell -File scripts\build_exe.ps1         # 构建 + 验证（构建脚本自带验证步骤）
```

打包这一层也被测试覆盖（`tests/test_packaging.py`）：spec 仍然指向两个入口、
图标真的编码成 ICO/PNG、清单仍然有可启动 Activity 和唯一那条权限、
Java 源码仍然一文件一顶层类、构建脚本仍然包含验证步骤，以及——两个 exe 都仍然
带着运行期钩子（包括设 `TCL_LIBRARY` 的那个），Tcl/Tk 载荷缺失或来自项目自己的
`dist\` 时，构建必须失败。

---

## 5. 故障排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `build_exe.ps1` 说 "no python.org CPython found" | PATH 里只有 MSYS2/mingw 的 python | 装 python.org 的 3.12，或用 `-Python C:\path\python.exe` |
| 窗口一闪而过 | 配置有问题 | 看 `%LOCALAPPDATA%\RevLab\logs\revlab-desktop.log` |
| 日志里有 `TclError: Can't find a usable init.tcl` | 运行期钩子 `pyi_rth__tkinter` 没进 exe（就没人设 `TCL_LIBRARY`），或 Tcl/Tk 库是从被污染的收集里拿的 | 见第 3 节第四个坑；`python scripts\gui_smoke_frozen.py` 会复现并打出日志尾部 |
| 双击后"开始分析"没反应 | 目标不可识别或未选 | 状态栏会说明；文件不存在/无法识别时不会静默 |
| 手机连不上 PC | 不同网段 / 防火墙拦了端口 | 确认同一 Wi-Fi；首次绑定会弹防火墙提示，允许即可 |
| 手机打开显示 `unauthorised` | 地址少了 `?t=<访问码>` | 从 PC 的日志/剪贴板取完整地址 |
| `build_apk.py` 说 d8 拒绝 class | 源码里又出现了嵌套/匿名类 | 见第 3 节；`check_toolchain.py` 复现 |
| APK 装不上（Android 11+） | `resources.arsc` 被压缩 | 构建脚本会自检并直接报错；不要手工重新压缩 APK |
