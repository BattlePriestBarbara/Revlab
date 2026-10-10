"""Heuristics: turn raw tool output into findings with a severity.

Kept separate from the parsers on purpose. Parsers answer "what is there"; this
module answers "what does it mean" -- and interpretations change far more often
than file formats do. Each rule is a small function with a threshold and a
comment explaining the threshold, so a reader can argue with it.
"""

from __future__ import annotations

import re
from pathlib import Path

from .evidence import Finding
from .elf import ElfInfo
from .pe import PeInfo

ENCRYPTED_ENTROPY = 7.7

ASSET_HEAVY_RATIO = 4.0
INTERESTING_PERMISSIONS = (
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE",
    "QUERY_ALL_PACKAGES", "READ_PHONE_STATE", "READ_SMS", "RECEIVE_SMS",
    "PACKAGE_USAGE_STATS",
)

ANTI_ANALYSIS_SYMBOLS = (
    "ptrace", "frida", "xposed", "substrate", "magisk", "anti_debug",
    "antidebug", "is_debugger", "debugger_", "tracerpid", "qemu", "emulator",
    "root_check", "signature_check", "integrity",
)

PACKER_LIB_HINTS = (
    "jiagu", "protect", "shell", "dexhelper", "mobisec", "tup", "secshell",
    "execmain", "libexec", "nqshield", "bangcle", "ijiami", "kiwi",
)
TLS_NAMES = ("libssl.so", "libcrypto.so", "libmbedtls", "libboringssl", "conscrypt")
_TOOLCHAIN = (
    ("clang", re.compile(r"clang version (\d+)"), 9),
    ("gcc", re.compile(r"GCC[:\s]+\(?[^)]*\)?\s*(\d+)"), 8),
)


def apk_findings(probe: dict) -> list[Finding]:
    out: list[Finding] = []
    flags = probe.get("flags", {})
    manifest = probe.get("manifest", {}) or {}
    entries = probe.get("entries", [])

    if probe.get("error"):
        out.append(
            Finding(
                id="apk-unreadable",
                title="APK 无法作为 ZIP 读取",
                severity="medium",
                stage="static",
                detail=str(probe["error"]),
                confidence=0.9,
                tags=["container"],
            )
        )
        return out

    # Encrypted DEX body: the container is readable, the code inside is not.
    bad_dex = [d for d in probe.get("dex", []) if d.get("looks_encrypted")]
    if bad_dex:
        out.append(
            Finding(
                id="dex-encrypted-body",
                title="DEX 主体不是明文代码（疑似加固/加密载荷）",
                severity="critical",
                stage="static",
                detail="; ".join(
                    f"{d['name']} ({d.get('size', 0)} B): {d.get('note', '')}" for d in bad_dex
                ),
                evidence=[d["name"] for d in bad_dex],
                confidence=0.8,
                tags=["packer", "dex"],
            )
        )

    # Large high-entropy members: a payload that is not code usually hides here.
    suspicious = [
        entry
        for entry in entries
        if entry["size"] >= (1048576) and entry["entropy"] >= ENCRYPTED_ENTROPY
    ]
    if suspicious:
        out.append(
            Finding(
                id="high-entropy-payload",
                title="大体积高熵成员（疑似加密数据段）",
                severity="medium",
                stage="static",
                detail=(
                    f"{len(suspicious)} 个成员熵 >= {ENCRYPTED_ENTROPY} bits/byte；"
                    "先确认由哪段代码读取它们，再决定是否值得做 dump"
                ),
                evidence=[f"{e['name']} ({e['size']} B, H={e['entropy']})" for e in suspicious[:10]],
                confidence=0.6,
                tags=["packer", "entropy"],
            )
        )

    # Assets dwarfing the code is the other place a loader hides its payload.
    asset_bytes = flags.get("asset_bytes", 0)
    dex_bytes = sum(dex.get("size", 0) for dex in probe.get("dex", []))
    if dex_bytes and asset_bytes > dex_bytes * ASSET_HEAVY_RATIO:
        out.append(
            Finding(
                id="assets-heavy",
                title="assets 体积远大于代码（载荷可能不在 DEX 里）",
                severity="medium",
                stage="static",
                detail=(
                    f"assets={asset_bytes} B 对比 dex={dex_bytes} B (比例 "
                            f"{asset_bytes / dex_bytes:.1f}x)；优先审计读取 assets 的代码路径"
                ),
                evidence=[item["name"] for item in probe.get("assets", {}).get("largest", [])[:5]],
                confidence=0.5,
                tags=["packer", "assets"],
            )
        )

    out.extend(_apk_manifest_findings(flags, manifest, probe))
    return out


def _apk_manifest_findings(flags: dict, manifest: dict, probe: dict) -> list[Finding]:
    out: list[Finding] = []
    target_sdk = int(manifest.get("target_sdk") or 0)

    if manifest.get("debuggable"):
        out.append(
            Finding(
                id="manifest-debuggable",
                title="应用声明 android:debuggable=true",
                severity="high",
                stage="static",
                detail="调试位打开意味着 jdwp/调试接口可用，也意味着该构建可能不是发布件",
                evidence=["AndroidManifest.xml:application@debuggable"],
                confidence=0.95,
                tags=["manifest"],
            )
        )

    if manifest.get("uses_clear_text_traffic") is True:
        out.append(
            Finding(
                id="manifest-cleartext-true",
                title="允许明文流量（usesCleartextTraffic=true）",
                severity="medium",
                stage="static",
                detail="明文流量让网络侧观测更容易，同时本身就是一个真实的安全问题",
                evidence=["AndroidManifest.xml:application@usesCleartextTraffic"],
                confidence=0.9,
                tags=["manifest", "network"],
            )
        )
    elif manifest.get("uses_clear_text_traffic") is None and target_sdk >= 28:
        out.append(
            Finding(
                id="manifest-cleartext-default",
                title="明文流量默认关闭（targetSdk>=28 且未显式声明）",
                severity="info",
                stage="static",
                detail="先确认 networkSecurityConfig，网络侧手段要在平台策略之内设计",
                evidence=[f"targetSdk={target_sdk}"],
                confidence=0.7,
                tags=["manifest", "network"],
            )
        )

    if not flags.get("v1_signature") and not flags.get("v2_signature_block"):
        out.append(
            Finding(
                id="no-signature",
                title="未发现 v1/v2 签名块（可能被重打包或裁剪）",
                severity="medium",
                stage="static",
                detail="签名块缺失会让部分运行环境拒绝加载；若样本来自第三方渠道，优先怀疑重打包",
                confidence=0.6,
                tags=["integrity"],
            )
        )

    interesting = sorted(
        {
            permission
            for permission in manifest.get("permissions", [])
            if any(key in permission for key in INTERESTING_PERMISSIONS)
        }
    )
    if interesting:
        out.append(
            Finding(
                id="manifest-sensitive-permissions",
                title="申请敏感权限（攻击面线索）",
                severity="medium",
                stage="static",
                detail="这些权限决定了值得审计的代码路径：悬浮窗、安装包、无障碍、跨包查询",
                evidence=interesting,
                confidence=0.85,
                tags=["manifest", "attack-surface"],
            )
        )

    if flags.get("multiple_dex"):
        out.append(
            Finding(
                id="multiple-dex",
                title="多 DEX 构建（存在动态加载空间）",
                severity="info",
                stage="static",
                detail=(
                    f"{len(probe.get('dex', []))} 个 classes*.dex；"
                    "大型应用常见，也常用来藏第二段代码"
                ),
                evidence=[dex.get("name", "?") for dex in probe.get("dex", [])],
                confidence=0.8,
                tags=["dex"],
            )
        )

    if flags.get("has_native_libs"):
        out.append(
            Finding(
                id="native-surface",
                title="包含 JNI 原生库（静态与动态都要覆盖）",
                severity="info",
                stage="static",
                detail=(
                    "ABI: "
                    + ", ".join(flags.get("abis", []))
                    + "；先做 ELF triage，再决定把 Ghidra 的编译预算花在哪个库上"
                ),
                evidence=[lib["member"] for lib in probe.get("native_libs", [])[:15]],
                confidence=0.9,
                tags=["jni"],
            )
        )

    if 0 < target_sdk < 24:
        out.append(
            Finding(
                id="old-target-sdk",
                title="targetSdk 偏低（平台侧防护较弱）",
                severity="low",
                stage="static",
                detail=f"targetSdk={target_sdk} 早于 Android 7.0 的行为收紧点",
                confidence=0.7,
                tags=["manifest"],
            )
        )
    return out


def elf_findings(infos: list[ElfInfo], summary: dict | None = None) -> list[Finding]:
    """Interpret a set of parsed ELF objects (typically one APK's lib/ tree)."""
    out: list[Finding] = []
    if not infos:
        return out

    # Anti-analysis symbols first: they decide whether dynamic analysis starts clean.
    defenders: dict[str, list[str]] = {}
    for info in infos:
        hits = sorted(
            {
                symbol
                for symbol in info.imports + info.exports
                if any(key in symbol.lower() for key in ANTI_ANALYSIS_SYMBOLS)
            }
        )
        if hits:
            defenders[Path(info.path).name] = hits[:12]
    if defenders:
        out.append(
            Finding(
                id="anti-analysis-symbols",
                title="原生库导入/导出了反调试·环境检测符号",
                severity="high",
                stage="static",
                detail=(
                    "这些符号指向自防护逻辑；动态分析前先定位调用点，"
                    "否则 hook 可能在被检测后立刻失效或让进程退出"
                ),
                evidence=[
                    f"{name}: {', '.join(symbols)}"
                    for name, symbols in list(defenders.items())[:8]
                ],
                confidence=0.65,
                tags=["anti-analysis", "jni"],
            )
        )

    # No Java_* exports but JNI_OnLoad present: the surface lives in RegisterNatives.
    register_only = [
        Path(info.path).name
        for info in infos
        if info.is_shared_library
        and "JNI_OnLoad" in info.exports
        and not [name for name in info.exports if name.startswith("Java_")]
    ]
    if register_only:
        out.append(
            Finding(
                id="register-natives-only",
                title="JNI 面只在 RegisterNatives 里（静态看不到 Java_* 入口）",
                severity="info",
                stage="static",
                detail=(
                    "这些库通过 JNI_OnLoad + RegisterNatives 绑定方法，符号表里不会出现 Java_*；"
                    "方法名要靠动态 hook 或 Ghidra 里的字符串/调用点还原"
                ),
                evidence=register_only[:15],
                confidence=0.8,
                tags=["jni", "dynamic-needed"],
            )
        )

    # Zero exports: nothing to hook by name, so the caller has to be found first.
    opaque = [
        Path(info.path).name
        for info in infos
        if info.is_shared_library and not info.exports
    ]
    if opaque:
        out.append(
            Finding(
                id="no-exported-symbols",
                title="存在零导出符号的共享库（自研加载器/加固组件特征）",
                severity="medium",
                stage="static",
                detail="没有任何导出符号的 .so 通常由自有加载逻辑使用，静态入口要靠 Ghidra 反查引用",
                evidence=opaque[:15],
                confidence=0.6,
                tags=["packer", "jni"],
            )
        )

    # Packer name hints are a lead, not a verdict: verify the load order.
    hinted = sorted(
        {
            Path(info.path).name
            for info in infos
            if any(hint in Path(info.path).name.lower() for hint in PACKER_LIB_HINTS)
        }
    )
    if hinted:
        out.append(
            Finding(
                id="packer-lib-name",
                title="库命名与已知加固/保护组件一致（待验证）",
                severity="medium",
                stage="static",
                detail="命名只是线索；验证方式是看它是否在启动早期加载并参与 DEX 解密",
                evidence=hinted[:15],
                confidence=0.5,
                tags=["packer"],
            )
        )

    # Vendored TLS: the version has to be checked separately (platform patches skip it).
    vendored = sorted(
        {
            needed
            for info in infos
            for needed in info.needed
            if any(name in needed.lower() for name in TLS_NAMES)
        }
    )
    if vendored:
        out.append(
            Finding(
                id="vendored-tls",
                title="自带 TLS 栈（版本需要单独确认）",
                severity="info",
                stage="static",
                detail="自带 libssl/libcrypto 意味着平台补丁不一定生效，值得记录版本做合规检查",
                evidence=vendored,
                confidence=0.8,
                tags=["crypto", "compliance"],
            )
        )

    # A .comment from an old compiler is a hint about long-lived third-party code.
    stale: dict[str, str] = {}
    for info in infos:
        if not info.banner:
            continue
        for kind, pattern, limit in _TOOLCHAIN:
            match = pattern.search(info.banner)
            if match and int(match.group(1)) < limit:
                stale[Path(info.path).name] = info.banner
    if stale:
        out.append(
            Finding(
                id="stale-toolchain",
                title="使用陈旧编译器构建（历史遗留组件线索）",
                severity="low",
                stage="static",
                detail=".comment 里的编译器版本可用于发现长期未更新的第三方组件",
                evidence=[f"{name}: {banner}" for name, banner in list(stale.items())[:10]],
                confidence=0.6,
                tags=["toolchain", "compliance"],
            )
        )

    # Last: if every shared object is stripped, plan around strings and xrefs.
    libraries = [info for info in infos if info.is_shared_library]
    if libraries and all(info.stripped for info in libraries):
        out.append(
            Finding(
                id="all-stripped",
                title="全部共享库均已 strip",
                severity="info",
                stage="static",
                detail="符号表不可用，按导出符号定位入口的策略会失效，应改为字符串/交叉引用驱动",
                evidence=[f"{len(libraries)} shared objects, "
                          f"{len(summary.get('by_abi', {})) if summary else 0} ABI(s)"],
                confidence=0.75,
                tags=["symbols"],
            )
        )
    return out


# ---- PE ---------------------------------------------------------------------
#
# Same split as the ELF rules: pe.py reports facts, this section decides what
# they mean. Two Windows binaries that import the same API are not equally
# interesting, so every rule below is about *which* combination is present.

#: "Write into someone else's process" -- the write half of an injection stub.
REMOTE_WRITE_APIS = (
    "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
)
#: The "run it" half: a thread (or an APC, or a hijacked context) in the target.
REMOTE_THREAD_APIS = (
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "ZwCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
    "SetThreadContext", "NtSetContextThread", "ResumeThread", "NtResumeThread",
)
#: Allocation and page-permission changes are kept apart because the *pair* is
#: what matters: a stub that decrypts itself needs both halves, while either
#: half alone shows up in half the binaries on a normal machine.
ALLOCATION_APIS = (
    "VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory",
    "ZwAllocateVirtualMemory", "RtlAllocateHeap", "HeapAlloc", "LocalAlloc",
    "GlobalAlloc", "CreateFileMappingA", "CreateFileMappingW",
)
MAPPING_APIS = (
    "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory",
    "ZwProtectVirtualMemory", "MapViewOfFile", "NtMapViewOfSection",
    "FlushInstructionCache", "VirtualQuery", "VirtualQueryEx",
)
#: Section names packers ship with. Renaming a section costs one edit, so this is
#: a lead and not a verdict: "UPX0" also appears in files that were unpacked.
PACKER_SECTIONS = (
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".packed", ".petite", ".mpress",
    ".themida", ".vmp0", "vmp0", ".vmp1", ".enigma", ".nsp0", ".nsp1", ".tpo",
)
#: Above this a large body is more likely ciphertext than code -- but compressed
#: resources look identical, so the size floor below keeps the number honest.
PACKED_ENTROPY = 7.0
MIN_SECTION_BYTES = 512


def pe_findings(infos: list[PeInfo], summary: dict | None = None) -> list[Finding]:
    """Interpret parsed PE objects (one staged directory, or one sample set).

    ``summary`` is optional and only used by the corpus-level rules: when the
    caller already has the record-sized batch view (``by_machine``) there is no
    reason to recount what the caller just counted.
    """
    out: list[Finding] = []
    for info in infos:
        out.extend(_pe_object_findings(info))

    machines = (summary or {}).get("by_machine") or {}
    if not machines:
        machines = {
            info.machine: sum(1 for other in infos if other.machine == info.machine)
            for info in infos
            if info.machine
        }
    if len(machines) > 1:
        out.append(
            Finding(
                id="pe-mixed-arch",
                title="同一批 PE 混用多种架构",
                severity="info",
                stage="static",
                detail="混放多平台组件时反编译预算要按架构分配，别拿 32 位的结论解释 64 位的调用",
                evidence=[f"{arch} x{count}" for arch, count in sorted(machines.items())],
                confidence=0.6,
                tags=["layout"],
            )
        )
    return out


def _pe_object_findings(info: PeInfo) -> list[Finding]:
    """Every rule that reads one PE: APIs, sections, entry point, signature."""
    out: list[Finding] = []
    name = Path(info.path).name
    if not info.valid:
        out.append(
            Finding(
                id="pe-unreadable",
                title="PE 头无法解析",
                severity="medium",
                stage="static",
                detail=str(info.error or "parse failed"),
                evidence=[name],
                confidence=0.9,
                tags=["container"],
            )
        )
        return out

    imported = set(info.imported_functions)
    writes = sorted(imported & set(REMOTE_WRITE_APIS))
    threads = sorted(imported & set(REMOTE_THREAD_APIS))
    allocations = sorted(imported & set(ALLOCATION_APIS))
    mappings = sorted(imported & set(MAPPING_APIS))

    if writes and threads:
        # A signed DLL importing this pair is usually the module that *implements*
        # it (kernel32 re-exports both). An unsigned image is the interesting one.
        system_side = info.is_dll and info.is_signed
        out.append(
            Finding(
                id="pe-injection-apis",
                title="导入进程注入 API（写内存 + 起线程）",
                severity="medium" if system_side else "high",
                stage="static",
                detail="在目标进程里写内存和在目标进程起线程的 API 同时出现；先确认这两半是否成对调用",
                evidence=sorted(set(writes + threads))[:12],
                confidence=0.5 if system_side else 0.85,
                tags=["injection", "winapi"],
            )
        )
    elif allocations or mappings:
        out.append(
            Finding(
                id="pe-memory-apis",
                title="导入内存分配/改页权限 API（自改代码或加载器线索）",
                severity="medium",
                stage="static",
                detail="分配与改页权限同时出现是自解密代码的常见组合；只有一半命中时它更可能只是 JIT/分配器",
                evidence=sorted(set(allocations + mappings))[:12],
                confidence=0.5 if allocations and mappings else 0.3,
                tags=["packer", "winapi"],
            )
        )

    packed = [
        section
        for section in info.sections
        if section.raw_size >= MIN_SECTION_BYTES and section.entropy >= PACKED_ENTROPY
    ]
    if packed:
        out.append(
            Finding(
                id="pe-high-entropy-section",
                title="大体积高熵段（疑似加壳/加密载荷）",
                severity="medium",
                stage="static",
                detail=(
                    f"{len(packed)} 个段熵 >= {PACKED_ENTROPY} bits/byte 且体积 >= "
                    f"{MIN_SECTION_BYTES} B；先看加载时是谁在写它，再决定要不要 dump"
                ),
                evidence=[
                    f"{section.name} ({section.raw_size} B, H={section.entropy})"
                    for section in packed[:10]
                ],
                confidence=0.6,
                tags=["packer", "entropy"],
            )
        )

    named = sorted(
        {
            section.name
            for section in info.sections
            if section.name.strip().lower() in PACKER_SECTIONS
        }
    )
    if named:
        out.append(
            Finding(
                id="pe-packer-sections",
                title="段名与已知加壳器一致（待验证）",
                severity="medium",
                stage="static",
                detail="段名改一个字节就没了；验证方式是看入口代码是否在解压自身",
                evidence=named,
                confidence=0.5,
                tags=["packer"],
            )
        )

    writable_code = [
        section
        for section in info.sections
        if "execute" in section.flags and "write" in section.flags and section.raw_size
    ]
    if writable_code:
        out.append(
            Finding(
                id="pe-writable-code",
                title="存在可写且可执行段（自改代码/解壳痕迹）",
                severity="medium",
                stage="static",
                detail="W+X 段意味着代码可以在运行时被改写：壳的跳板这样干，JIT 运行时也这样干",
                evidence=[
                    f"{section.name} ({', '.join(section.flags)})"
                    for section in writable_code[:8]
                ],
                confidence=0.5,
                tags=["packer", "memory"],
            )
        )

    entry_sections = [
        section
        for section in info.sections
        if section.virtual_address <= info.entry_point
        < section.virtual_address + max(section.virtual_size, section.raw_size)
    ]
    if info.entry_point and not any(
        "execute" in section.flags for section in entry_sections
    ):
        out.append(
            Finding(
                id="pe-entry-not-code",
                title="入口点不在可执行段内（壳/加载器线索）",
                severity="medium",
                stage="static",
                detail="入口落在非代码段，说明真正的入口要么被壳接管，要么到运行时才生成",
                evidence=[
                    f"entry=0x{info.entry_point:x}",
                    *(section.name for section in entry_sections[:4]),
                ],
                confidence=0.6,
                tags=["packer"],
            )
        )

    if not info.imports:
        out.append(
            Finding(
                id="pe-no-imports",
                title="导入表为空（API 可能是运行时解析）",
                severity="medium",
                stage="static",
                detail="没有导入表意味着 API 走 LoadLibrary/GetProcAddress 之类拿到，静态符号线索会断",
                evidence=[name],
                confidence=0.6,
                tags=["winapi"],
            )
        )

    if info.is_signed:
        out.append(
            Finding(
                id="pe-signed",
                title="附带签名块（存在不等于验证通过）",
                severity="info",
                stage="static",
                detail=(
                    f"证书表在 0x{info.signature_offset:x}，{info.signature_size} B；"
                    "这里只能证明签名被附带，验证要交给 signtool/osslsigncode"
                ),
                evidence=[name],
                confidence=0.9,
                tags=["integrity"],
            )
        )
    else:
        out.append(
            Finding(
                id="pe-unsigned",
                title="未附带签名块（来源与重打包线索）",
                severity="low",
                stage="static",
                detail="没有证书表说明这份二进制没带发布者签名；先确认来源，再谈它是否可疑",
                evidence=[name],
                confidence=0.6,
                tags=["integrity"],
            )
        )

    if info.is_dotnet:
        out.append(
            Finding(
                id="pe-dotnet",
                title=".NET 程序集（先走 IL 工具链）",
                severity="info",
                stage="static",
                detail="CLR 目录或 mscoree.dll 说明这是托管程序集：ILSpy/dnSpy 比 Ghidra 便宜得多",
                evidence=["CLR directory or mscoree.dll"],
                confidence=0.8,
                tags=["dotnet"],
            )
        )

    missing = [flag for flag in ("nx-compat", "dynamic-base") if flag not in info.dll_flags]
    if len(missing) == 2:
        out.append(
            Finding(
                id="pe-missing-mitigations",
                title="未启用 DEP/ASLR 编译标志（平台侧防护较弱）",
                severity="medium",
                stage="static",
                detail="DllCharacteristics 里既没有 NX 也没有动态基址：可能是老工具链，也可能是刻意留的空间",
                evidence=[f"missing: {', '.join(missing)}"],
                confidence=0.6,
                tags=["hardening"],
            )
        )

    if not info.timestamp_iso:
        out.append(
            Finding(
                id="pe-odd-timestamp",
                title="编译时间戳不可信（清零或被改写）",
                severity="info",
                stage="static",
                detail="COFF 时间戳不在合理区间内，这是常见的清零/置未来值手法，别用它给样本排序",
                evidence=[f"timestamp=0x{info.timestamp:08x}"],
                confidence=0.6,
                tags=["metadata"],
            )
        )

    if info.warnings:
        out.append(
            Finding(
                id="pe-structural-warnings",
                title="PE 结构有异常（能读到的比声明的少）",
                severity="info",
                stage="static",
                detail="结构告警说明文件被裁剪或被刻意做坏；先解决这些，再解释内容",
                evidence=[str(item) for item in info.warnings[:6]],
                confidence=0.7,
                tags=["structure"],
            )
        )
    return out
