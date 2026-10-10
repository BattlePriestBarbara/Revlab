# 03 — 工作流：一条可复现的分析路线

原则：**先便宜的手段，后昂贵的引擎；每一阶段都留下可引用的事实。**

## 阶段 0 — 体检与授权

```powershell
python -m revlab doctor
python -m revlab scope
```

`doctor` 有 error 就别急着往下走：Ghidra/JDK/Frida 的问题在做完三小时分析后才发现是最亏的。
`scope` 为空意味着动态能力全部关闭——这是默认值。

## 阶段 1 — 静态三连（秒级到分钟级，零依赖）

```powershell
python scripts/make_demo_apk.py            # 没有样本时：合成一个（加密 DEX + 高熵资产 + 两个 .so）
python -m revlab triage C:\samples\demo.apk --abi x86_64
```

一次调用做四件事：

1. **AXML 清单**：包名、版本、`minSdk/targetSdk`、入口 Application 类、
   `debuggable`、`usesCleartextTraffic`、`extractNativeLibs`、权限、组件；
2. **ZIP 清单 + 熵**：每个成员的大小/压缩率/熵值，按大小排序；
3. **DEX 体检**：读 DEX 头，判断"声明大小 vs 实际大小""class_defs 是否为 0""正文熵"，
   得出"这段是不是真代码"；
4. **原生库 ELF triage**：ABI、SONAME、`DT_NEEDED`、导出/导入符号、`Java_*`/`JNI_OnLoad`
   入口、`.comment` 编译器横幅、是否 strip。

产物落在 `workspaces\<target>-<hash>\`：`records.jsonl`、`findings.jsonl`、
`artifacts/apk-probe.json`、`artifacts/elf-triage.json`，并解包 `artifacts/native/`、
`artifacts/dex/` 供后续阶段使用。

**怎么读结论**：`findings` 里 `dex-encrypted-body` 或 `high-entropy-payload` 出现，
说明这一版 APK 的代码主体不是明文——先决定"要不要继续"再决定"用什么工具"。

## 阶段 2 — Ghidra（把预算花在值得的库上）

先用 MCP 问问题（热 JVM 便宜），要批量再用 headless。

```powershell
python -m revlab ghidra tools
python -m revlab ghidra call list_functions --args "{\"limit\": 50}"
python -m revlab ghidra call decompile_function --args "{\"function_name\": \"JNI_OnLoad\"}"

python -m revlab ghidra summary workspaces\...\artifacts\native\lib\x86_64\libfoo.so `
       --filter crypt --max-functions 30
```

headless 路线会跑内置后置脚本 `ExportProgramSummary.java`，产出：

- 程序信息（语言、编译器、image base、SHA-256）、函数总数；
- 按**被引用次数**排序的函数表（授权检查、加解密例程通常被多处调用，叶子函数通常不是）；
- 定义字符串（含地址）、符号表、导入；
- 高引用函数的前 N 个反编译 C 文本。

选择顺序建议：先看 `register-natives-only`（静态看不到 `Java_*`）的库，
再按 ABI 与体积决定谁值得反编译。

## 阶段 3 — Frida（一次问答一个 hook）

```powershell
python -m revlab dynamic devices
python -m revlab dynamic server start --abi x86_64
python -m revlab dynamic run com.example.demo --hook api_probe --seconds 45
python -m revlab dynamic run com.example.demo --hook jni_boundary --seconds 45
python -m revlab dynamic run 4711 --hook dex_watch --seconds 90
```

| hook | 回答的问题 |
| --- | --- |
| `api_probe` | 它到底碰了哪些文件、起了哪些进程、用了哪些 Java IO/ZIP API |
| `anti_debug_probe` | 它在什么时候检查自己是否被调试（ptrace `/proc/self/*`/`Debug.*`） |
| `jni_boundary` | 运行时把哪些 Java 方法绑到了哪个 native 地址（`RegisterNatives`） |
| `dex_watch` | 运行期是否出现 DEX 形态的写入/加载（有则 dump 到 `/data/local/tmp`） |

每次运行都会写出 `artifacts/frida-<hook>.jsonl`，并生成发现：

- `runtime-dex-writes-*`（high）：确实在运行期改写 DEX；
- `runtime-jni-bindings-*`（medium）：拿到了静态符号表里没有的 JNI 三元组；
- `anti-analysis-observed-*`（medium）：自检被触发；
- `hook-silent-*`（info）：**零命中也是结论**，别重复第二次。

## 阶段 4 — 报告

```powershell
python -m revlab report --target latest
```

`report.md` 便于 diff 与评审，`report.html` 是自包含单文件（无 CDN，可以随样本一起归档）。
报告结构：结论摘要 → 发现明细（严重性/置信度/证据）→ 分析记录 → 证据产物 →
下一步建议（由发现标签推导）→ 范围与免责。

## 阶段 5 — 助手驱动（可选）

把 RevLab 装成 MCP 服务器（见 `04-mcp-integration.md`），然后一句话交给助手：

> 用 revlab_doctor 确认环境，triage 一下 demo.apk，把值得看的库用 ghidra_summary 反编译，
> 再跑 dex_watch 看运行期有没有 DEX 写入，最后生成报告，并告诉我哪一条结论的证据最弱。

## 反模式（踩过的坑）

1. **不看清单就开 Ghidra**：`extractNativeLibs=false` 的时候库是从 APK 里直接映射的，
   动态分析的模块名与路径和你以为的不一样；
2. **spawn 优先**：目标在启动后极短时间内自杀时，spawn 工作流会把时间全浪费掉；
3. **反复重试同一个 hook**：零命中就是结论，换路线（定位解密函数）比重试有用；
4. **把"没观测到"说成"不存在"**：报告里 `hook-silent` / `all-stripped` 这类发现
   就是在提醒结论强度；
5. **忽略版本耦合**：frida 绑定与 server 版本、Ghidra 与 JDK 版本，不一致时错误信息全都指向错误的方向。
