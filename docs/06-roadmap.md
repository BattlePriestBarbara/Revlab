# 06 — 路线图：从可用到好用

当前版本（0.2.0）是一个**端到端可用、并且点开就能用**的工作台：
静态三连、Ghidra 双路线、Frida 四个 hook、证据与报告、双向 MCP，
外加可以双击运行的桌面窗口（`dist\RevLab\RevLab.exe`）与手机端客户端
（`dist\RevLab-Mobile-0.2.0.apk`）。下面按"下一步最有价值"排序。

## P0 — 打通闭环（已具备，需要真机验证）

- [ ] 在真实设备/模拟器上跑通 `doctor → server start → run dex_watch` 全链路；
- [ ] 用真实样本校验熵阈值与 DEX 加密判定，把误报率写入 `05-scope-and-limits.md`；
- [ ] 用真实 Ghidra MCP 服务器验证 `TOOL_CANDIDATES` 的解析覆盖率。

## P1 — 分析深度

- [ ] **DEX → smali/Java 视图**：把 `dex_watch` dump 出的 DEX 交给反编译器，产出可读代码；
- [ ] **字符串驱动的交叉引用**：在 headless 后置脚本里增加"字符串 → 引用函数 → 反编译"
  的第三段流程（现在的排序只按引用次数）；
- [ ] **JNI 绑定回填**：把 `jni_boundary` 拿到的 `(name, signature, address)` 写回 Ghidra 项目
  （改名 + 注释），让静态视图直接带上动态事实；
- [ ] **网络面观测**：`ssl_write/ssl_read` 长度与明文判定（在授权与平台策略之内）。

## P2 — 工程化

- [ ] **并行引擎**：Ghidra 批处理与 Frida 观测同时进行（互不阻塞），结果在会话层合并；
- [ ] **会话对比**：两次 triage 的 diff（同一 App 两个版本），报告里直接给出"新增的可疑面"；
- [x] **CI 门**：`unittest` + `py_compile` + `node --check` + `gui_smoke` + `gui_smoke_frozen` + `doctor --json` 都已就位；
- [ ] **Web UI 增强**：进度流式输出（现在长任务只能等）、发现过滤、报告内嵌预览；
- [x] **桌面打包**：`scripts\build_exe.ps1` 产出 `RevLab.exe` / `RevLabCLI.exe`
  （构建脚本自带验证：拷到 %TEMP% 启动后找出那个窗口），见 `07-packaging.md`；
- [x] **Android 客户端**：`android\build_apk.py` 产出 WebView 客户端 APK（免 Gradle）；
- [ ] **pipx / wheel 安装**：`pipx install .` 之后 `revlab` 直接可用
  （pyproject 的 package-data 已覆盖 hooks/ghidra_scripts，但还没在干净环境里验证过）；
- [ ] **给 APK 一个更聪明的第二屏**：现在的手机端只是镜像面板；下一步是"只看发现 + 一键生成报告"。

## P3 — 覆盖面

- [ ] **Windows / Linux 目标**：PE 与 ELF 可执行文件的 triage（当前 ELF 已覆盖 `.so`/`.elf`）；
- [ ] **iOS/Mach-O**：Mach-O 头与 `LC_LOAD_DYLIB` 解析（Frida 侧基本不需要改）；
- [ ] **更多 hook**：Keystore/SharedPreferences/WebView、剪贴板、动态权限请求；
- [ ] **规则可插拔**：把 `heuristics.py` 的阈值与规则搬到 TOML，允许团队自定义严重性映射。

## 明确不做

- 不提供"一键脱壳/破解"能力：本工具只做观测与证据整理；
- 不内置任何第三方样本或指纹库：发现的准确率由使用者自己的样本决定；
- 不自动联网、不上传任何证据：所有数据留在本地会话目录。
