# 05 — 范围、合规与已知限制

## 1. 授权门禁是默认拒绝

`revlab.toml`：

```toml
[scope]
authorised = ["com.example.demo", "demo.apk", "c:\\lab\\samples\\mine"]
```

规则很朴素：目标字符串与某一项互为子串（忽略大小写）即视为授权。
匹配发生在**每一个会接触样本或设备的入口**：

- `triage` / `elf` 在读取样本前校验；
- `dynamic_pass` 在执行任何 hook 前校验；
- MCP 工具同路：`revlab_triage_apk`、`revlab_frida_run` 都会走同一道门，
  被拒绝时返回 `isError: true` 并说明原因（不会静默降级）。

列表为空时——也就是默认值——动态能力全部不可用。这是刻意的：
"分析自己的样本"是一个需要被写下来的动作，不是一个默认生效的开关。

桌面窗口同样遵守这条：被门禁拒绝时，它只会切到「授权范围」页、把目标文件名填进输入框
（点"添加"再"保存到配置"即可重试），**绝不替用户授权任何东西**——包括它自己刚生成的
合成样本。手机客户端与 Web UI 走的是同一道门，没有旁路。

## 2. 使用边界

只对你拥有、或明确获得授权测试的软件使用——包括你所在组织允许测试的自研/采购件、
CTF 环境、以及供应商明确许可的评估。本工具**不提供**任何绕过保护以获取他人数据的能力，
它只描述观测方法：怎么读清单、怎么算熵、怎么问 Ghidra、怎么用 Frida 做一次单点观测。

报告末节固定包含范围与免责声明，证据链（records/findings）保证结论可复核。

## 3. 方法上的已知限制（不是 bug）

| 限制 | 影响 | 应对 |
| --- | --- | --- |
| ELF triage 不做重定位/控制流 | 看不到间接调用关系 | 交给 Ghidra；RevLab 只做"值不值得反编译"的判断 |
| 熵阈值是启发式 | 压缩数据也可能高熵 | 结论带置信度（0.5–0.6），并要求后续验证 |
| 静态符号表缺失（strip） | 无法按名字定位入口 | 发现 `all-stripped`；改用字符串/交叉引用驱动 |
| `RegisterNatives` 绑定 | 静态看不到 `Java_*` | `jni_boundary` 动态捕获三元组后回填 Ghidra |
| 翻译层/模拟器 | 部分 hook 按构造不可达 | 这是计划约束：先定环境再谈覆盖率 |
| 加固（指令级 + DEX→C） | 可能不存在完整明文载荷 | 报告把"零命中"写成排除性结论，而不是继续重试 |
| 应用层反调试 | hook 可能被检测或进程退出 | 前置 hook / spawn 模式；把自检时点写成发现 |
| 引擎版本耦合 | 版本不一致时错误信息误导 | `doctor` 的版本匹配检查 + 拒绝启动 |

## 4. 隐私与数据处理

- 工作区默认落在 `workspaces/`，`.gitignore` 已排除样本、DEX、`.so`、报告与 `revlab.toml`；
- 证据里会出现路径、包名、字符串常量——这些可能含个人信息，归档前自己过一遍；
- 报告是自包含 HTML，没有外部资源请求，适合离线归档；
- 任何阶段都不主动联网：只有你自己调用的 Frida hook 会触发目标自身的网络行为；
- 唯一的网络服务是你自己打开的本地界面：默认只监听 `127.0.0.1`；绑定到真实网卡时
  **没有访问码就拒绝启动**，访问码只出现在 URL 参数或 `X-RevLab-Token` 头里，
  并且访问日志会把 query string 抹掉（日志文件正是密钥最容易泄漏的地方）。
  手机客户端因此只拿到"界面"，拿不到额外权限。

## 5. 提交前检查（本项目自身的质量门）

```powershell
python -m unittest discover -s tests -t .     # 137 tests，离线可跑
python -m py_compile revlab\*.py
node --check revlab\hooks\api_probe.js        # 4 个 hook 同理
python scripts\gui_smoke.py                   # 桌面窗口：真建窗口、真点按钮
python scripts\gui_smoke_frozen.py            # 冻结版：拷到 %TEMP% 启动，再找那个窗口（需先构建）
python android\check_toolchain.py             # 手机端 dex 步骤能力自检
python -m revlab doctor --json                # 机器可读的环境报告
```

把这些写进 CI 时，注意：单元测试不需要 Ghidra/Frida/真机，环境相关的检查
应该作为独立门（`doctor`），而不是塞进单元测试。
