"""Dependency-free ELF triage.

Why hand-rolled instead of ``pyelftools``: the first question in any workflow is
"what am I even looking at", and that question must be answerable on a fresh
machine with no wheels installed and no virtual environment. A dependency-free
pass over 50 shared objects takes seconds and decides where the expensive
decompilation budget goes. When something more exotic is needed, the same data
comes back from Ghidra anyway.

Covered: ELF class/endianness/type/machine, entry point, section table, SONAME,
DT_NEEDED, RPATH/RUNPATH, version banner (``.comment``), symbol-table presence
(``stripped``), exported functions, undefined imports, build-id.

Not covered (deliberately, they are Ghidra's job): relocations, decompilation,
control flow.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

ET = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
EM = {
    3: "x86", 8: "MIPS", 20: "PPC", 21: "PPC64", 22: "S390",
    40: "ARM", 62: "x86_64", 183: "aarch64", 243: "riscv",
}
SHT = {
    1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM",
    14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY",
    17: "GROUP", 18: "SYMTAB_SHNDX", 0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFD: "VERDEF", 0x6FFFFFFE: "VERNEED", 0x6FFFFFFF: "VERSYM",
}
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH = 1, 5, 10, 14, 15, 29
STT_FUNC, STB_GLOBAL, STB_WEAK = 2, 1, 2


@dataclass
class Section:
    name: str
    type_id: int
    type_name: str
    offset: int
    size: int
    entsize: int
    link: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ElfInfo:
    path: str
    valid: bool = False
    error: str | None = None
    bits: int = 0
    endian: str = "little"
    type_id: int = 0
    type_name: str = ""
    machine_id: int = 0
    machine: str = ""
    entry: int = 0
    soname: str = ""
    needed: list[str] = field(default_factory=list)
    rpath: str = ""
    runpath: str = ""
    banner: str = ""
    build_id: str = ""
    stripped: bool = True
    sections: list[Section] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    size: int = 0
    sha256: str = ""

    # ---- convenience -------------------------------------------------------
    @property
    def abi(self) -> str:
        arch = self.machine or f"machine{self.machine_id}"
        return f"{arch}-{self.bits}"

    @property
    def is_shared_library(self) -> bool:
        return self.type_id == 3

    @property
    def section_names(self) -> list[str]:
        return [section.name for section in self.sections]

    @property
    def jni_entry_points(self) -> list[str]:
        """Exports a Java VM can actually reach: JNI_OnLoad + Java_* symbols."""
        return [
            name
            for name in self.exports
            if name == "JNI_OnLoad" or name.startswith("Java_")
        ]

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["abi"] = self.abi
        payload["export_count"] = len(self.exports)
        payload["import_count"] = len(self.imports)
        payload["jni_entry_points"] = self.jni_entry_points
        payload["sections"] = [section.name for section in self.sections]
        return payload


def is_elf(path: str | Path, probe: int = 4) -> bool:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(probe) == ELF_MAGIC
    except OSError:
        return False


#: First bytes -> what the file really is. An operator who points ``revlab elf``
#: at a Windows .exe deserves the name of the format and the command that can
#: actually read it -- not "0 objects, no findings", which reads like "this
#: binary is empty" and is worse than an error.
MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xca\xfe\xba\xbe", "mach-o-universal"),
    (b"\xfe\xed\xfa\xce", "mach-o-32"),
    (b"\xfe\xed\xfa\xcf", "mach-o-64"),
    (b"\xce\xfa\xed\xfe", "mach-o-32-le"),
    (b"\xcf\xfa\xed\xfe", "mach-o-64-le"),
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"%PDF", "pdf"),
)

#: What to do about a format this pass cannot read.
NEXT_STEP = {
    "pe": "Windows PE/COFF -- `revlab ghidra summary <path>` (Ghidra reads PE directly)",
    "mach-o-64": "Mach-O -- `revlab ghidra summary <path>`",
    "mach-o-32": "Mach-O -- `revlab ghidra summary <path>`",
    "mach-o-64-le": "Mach-O -- `revlab ghidra summary <path>`",
    "mach-o-32-le": "Mach-O -- `revlab ghidra summary <path>`",
    "mach-o-universal": "Mach-O universal -- extract the slice first, then `revlab ghidra summary`",
    "dex": "Dalvik bytecode -- `revlab triage <apk>` for the container, or `revlab ghidra summary <path>`",
    "zip": "archive -- `revlab triage <path>` if it is an APK/AAB",
    "gzip": "gzip -- decompress first (the payload is usually an APK or a DEX)",
    "pdf": "PDF -- not a binary; this workbench does not analyse documents",
    "empty": "zero bytes -- the file is empty or the copy failed",
    "unreadable": "cannot be read (permissions, or the path vanished)",
    "unknown": "unrecognised format -- no magic matched; check for encryption or a partial dump",
}


def sniff(source: str | Path | bytes, probe: int = 8) -> str:
    """Identify a file (or an in-memory buffer) from its magic bytes.

    Accepts ``bytes`` as well as a path so callers that already hold a ZIP
    member or a memory dump can ask the same question without a temp file.
    """
    if isinstance(source, (bytes, bytearray)):
        head = bytes(source[:probe])
    else:
        try:
            with Path(source).open("rb") as handle:
                head = handle.read(probe)
        except OSError:
            return "unreadable"
    if not head:
        return "empty"
    for magic, kind in MAGIC_SIGNATURES:
        if head.startswith(magic):
            return kind
    return "unknown"


def skip_reason(kind: str) -> str:
    """Why *kind* is not ELF, and which command handles it instead."""
    if kind == "elf":
        return ""
    return f"not an ELF (detected {kind}); {NEXT_STEP.get(kind, NEXT_STEP['unknown'])}"


def _read_cstring(blob: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset, offset + limit)
    if end == -1:
        end = min(len(blob), offset + limit)
    return blob[offset:end].decode("utf-8", "replace")


class _Reader:
    """Little/big-endian, 32/64-bit aware accessor over a bytes buffer."""

    def __init__(self, blob: bytes, bits: int, endian: str):
        self.blob = blob
        self.bits = bits
        self.end = "<" if endian == "little" else ">"

    def _fmt(self, code64: str, code32: str) -> str:
        return self.end + (code64 if self.bits == 64 else code32)

    def u16(self, offset: int) -> int:
        return struct.unpack_from(self.end + "H", self.blob, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from(self.end + "I", self.blob, offset)[0]

    def addr(self, offset: int) -> int:
        return struct.unpack_from(self._fmt("Q", "I"), self.blob, offset)[0]

    def slice(self, offset: int, size: int) -> bytes:
        return self.blob[offset : offset + size]


def _parse_sections(reader: _Reader, e_shoff: int, e_shentsize: int, e_shnum: int,
                    e_shstrndx: int) -> list[Section]:
    raw: list[tuple[int, int, int, int, int, int]] = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        if base + 8 > len(reader.blob):
            break
        name_off = reader.u32(base)
        type_id = reader.u32(base + 4)
        if reader.bits == 64:
            offset, size = reader.addr(base + 24), reader.addr(base + 32)
            link, entsize = reader.u32(base + 40), reader.addr(base + 56)
        else:
            offset, size = reader.u32(base + 16), reader.u32(base + 20)
            link, entsize = reader.u32(base + 24), reader.u32(base + 36)
        raw.append((name_off, type_id, offset, size, link, entsize))

    # Section extensions: shnum==0 -> sh_size of section 0,
    # shstrndx==0xFFFF -> sh_link of section 0.
    if e_shnum == 0 and raw and raw[0][3]:
        e_shnum = raw[0][3]
    if e_shstrndx == 0xFFFF and raw:
        e_shstrndx = raw[0][4]

    names = b""
    if 0 <= e_shstrndx < len(raw):
        _, _, offset, size, _, _ = raw[e_shstrndx]
        names = reader.slice(offset, size)

    sections: list[Section] = []
    for name_off, type_id, offset, size, link, entsize in raw:
        sections.append(
            Section(
                name=_read_cstring(names, name_off, 128),
                type_id=type_id,
                type_name=SHT.get(type_id, hex(type_id)),
                offset=offset,
                size=size,
                entsize=entsize,
                link=link,
            )
        )
    return sections


def _load_segments(reader: _Reader, e_phoff: int, e_phentsize: int, e_phnum: int):
    """Return (load_map, dynamic_segment) straight from the program headers."""
    load_map: list[tuple[int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    for index in range(e_phnum):
        base = e_phoff + index * e_phentsize
        if base + 8 > len(reader.blob):
            break
        p_type = reader.u32(base)
        if reader.bits == 64:
            p_offset, p_vaddr = reader.addr(base + 8), reader.addr(base + 16)
            p_filesz, p_memsz = reader.addr(base + 32), reader.addr(base + 40)
        else:
            p_offset, p_vaddr = reader.u32(base + 4), reader.u32(base + 8)
            p_filesz, p_memsz = reader.u32(base + 16), reader.u32(base + 20)
        if p_type == PT_LOAD:
            load_map.append((p_vaddr, p_offset, p_memsz))
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)
    return load_map, dynamic


def _vaddr_to_offset(load_map, vaddr: int) -> int | None:
    for seg_vaddr, seg_offset, seg_memsz in load_map:
        if seg_vaddr <= vaddr < seg_vaddr + seg_memsz:
            return seg_offset + (vaddr - seg_vaddr)
    return None


def _parse_dynamic(reader: _Reader, dynamic) -> dict[str, list[int]]:
    """Dynamic entries we care about, keyed by DT_ tag string."""
    if dynamic is None:
        return {}
    dyn_offset, dyn_size = dynamic
    entsize = 16 if reader.bits == 64 else 8
    entries: dict[str, list[int]] = {}
    for offset in range(dyn_offset, dyn_offset + dyn_size, entsize):
        if offset + entsize > len(reader.blob):
            break
        tag = reader.addr(offset)
        value = reader.addr(offset + (8 if reader.bits == 64 else 4))
        if tag == 0:
            break
        if tag in (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_STRTAB, DT_STRSZ):
            entries.setdefault(str(tag), []).append(value)
    return entries


def _parse_symbols(reader: _Reader, sections: list[Section]) -> tuple[list[str], list[str]]:
    """(exports, imports) from .dynsym/.symtab when the section table survives."""
    exports: list[str] = []
    imports: list[str] = []
    tables = {".dynsym", ".symtab"}
    for section in sections:
        if section.name not in tables:
            continue
        link = sections[section.link] if 0 <= section.link < len(sections) else None
        strings = reader.slice(link.offset, link.size) if link else b""
        if not strings:
            continue
        entsize = section.entsize or (24 if reader.bits == 64 else 16)
        for offset in range(section.offset, section.offset + section.size, entsize):
            if offset + entsize > len(reader.blob):
                break
            name_off = reader.u32(offset)
            if name_off == 0:
                continue
            if reader.bits == 64:
                info_byte, shndx = reader.blob[offset + 4], reader.u16(offset + 6)
            else:
                info_byte, shndx = reader.blob[offset + 12], reader.u16(offset + 14)
            name = _read_cstring(strings, name_off, 256)
            if not name:
                continue
            bind, stype = info_byte >> 4, info_byte & 0xF
            if shndx == 0:
                imports.append(name)
            elif stype == STT_FUNC and bind in (STB_GLOBAL, STB_WEAK):
                exports.append(name)
    return sorted(set(exports)), sorted(set(imports))


def _parse_note_build_id(reader: _Reader, sections: list[Section]) -> str:
    for section in sections:
        if section.name != ".note.gnu.build-id" or section.size < 16:
            continue
        namesz, descsz = reader.u32(section.offset), reader.u32(section.offset + 4)
        desc_start = section.offset + 12 + ((namesz + 3) // 4) * 4
        return reader.slice(desc_start, descsz).hex()
    return ""


def parse(path: str | Path) -> ElfInfo:
    """Parse one ELF file into an :class:`ElfInfo` (never raises on bad input)."""
    target = Path(path)
    info = ElfInfo(path=str(target))
    try:
        data = target.read_bytes()
    except OSError as exc:
        info.error = f"cannot read file: {exc}"
        return info

    info.size = len(data)
    info.sha256 = hashlib.sha256(data).hexdigest()
    if len(data) < 64 or not data.startswith(ELF_MAGIC):
        info.error = "not an ELF image (bad magic)"
        return info

    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        info.error = f"unknown ELF class {ei_class}"
        return info
    if ei_data not in (1, 2):
        info.error = f"unknown ELF data encoding {ei_data}"
        return info

    bits = 64 if ei_class == 2 else 32
    endian = "little" if ei_data == 1 else "big"
    reader = _Reader(data, bits, endian)

    info.bits, info.endian = bits, endian
    info.type_id = reader.u16(16)
    info.type_name = ET.get(info.type_id, f"type{info.type_id}")
    info.machine_id = reader.u16(18)
    info.machine = EM.get(info.machine_id, f"machine{info.machine_id}")
    info.entry = reader.addr(24)

    if bits == 64:
        e_phoff, e_shoff = reader.addr(32), reader.addr(40)
        e_phentsize, e_phnum = reader.u16(54), reader.u16(56)
        e_shentsize, e_shnum, e_shstrndx = reader.u16(58), reader.u16(60), reader.u16(62)
    else:
        e_phoff, e_shoff = reader.addr(28), reader.addr(32)
        e_phentsize, e_phnum = reader.u16(42), reader.u16(44)
        e_shentsize, e_shnum, e_shstrndx = reader.u16(46), reader.u16(48), reader.u16(50)

    info.sections = _parse_sections(reader, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    info.stripped = ".symtab" not in info.section_names
    info.banner = _first_comment_line(reader, info.sections)
    info.build_id = _parse_note_build_id(reader, info.sections)
    info.exports, info.imports = _parse_symbols(reader, info.sections)

    load_map, dynamic = _load_segments(reader, e_phoff, e_phentsize, e_phnum)
    entries = _parse_dynamic(reader, dynamic)
    strings = b""
    strtab_vaddr = (entries.get(str(DT_STRTAB)) or [0])[0]
    if strtab_vaddr:
        offset = _vaddr_to_offset(load_map, strtab_vaddr)
        if offset is not None:
            size = (entries.get(str(DT_STRSZ)) or [4096])[0]
            strings = reader.slice(offset, size)
    if not strings:
        for section in info.sections:
            if section.name == ".dynstr":
                strings = reader.slice(section.offset, section.size)
                break

    if strings:
        info.needed = sorted(
            {
                _read_cstring(strings, value, 256)
                for value in entries.get(str(DT_NEEDED), [])
            }
            - {""}
        )
        soname = entries.get(str(DT_SONAME)) or [0]
        if soname[0]:
            info.soname = _read_cstring(strings, soname[0], 256)
        rpath = entries.get(str(DT_RPATH)) or [0]
        if rpath[0]:
            info.rpath = _read_cstring(strings, rpath[0], 512)
        runpath = entries.get(str(DT_RUNPATH)) or [0]
        if runpath[0]:
            info.runpath = _read_cstring(strings, runpath[0], 512)

    info.valid = True
    return info


def _first_comment_line(reader: _Reader, sections: list[Section]) -> str:
    for section in sections:
        if section.name != ".comment" or not section.size:
            continue
        blob = reader.slice(section.offset, min(section.size, 4096))
        text = blob.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        if text:
            return text.splitlines()[0][:240]
    return ""


DEFAULT_PATTERNS = ("*.so", "*.elf", "*.dylib", "*.bin", "*.node")


@dataclass
class Skipped:
    """A path that was looked at and deliberately not parsed."""

    path: str
    kind: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TriageResult:
    """Parsed objects plus the files that turned out not to be ELF."""

    objects: list[ElfInfo] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)

    @property
    def unsupported_reason(self) -> str:
        """Message for the "you gave me one file and it is not ELF" case."""
        if self.objects or not self.skipped:
            return ""
        return self.skipped[0].reason


#: How many files a "nothing matched" note will sniff before it stops.
SCAN_LIMIT = 200


def _describe_directory(base: Path, patterns: tuple[str, ...]) -> Skipped | None:
    """Explain an empty directory scan: what was looked for, what was there."""
    files = 0
    kinds: dict[str, int] = {}
    for entry in base.rglob("*"):
        if not entry.is_file():
            continue
        files += 1
        if files <= SCAN_LIMIT:
            kind = sniff(entry)
            kinds[kind] = kinds.get(kind, 0) + 1
    if not kinds:
        return None

    ranked = sorted(kinds.items(), key=lambda item: (-item[1], item[0]))
    shown = ", ".join(f"{kind} x{count}" for kind, count in ranked[:4])
    dominant = ranked[0][0]
    hint = NEXT_STEP.get(dominant, "")
    reason = (
        f"no ELF under {base}: nothing matched {', '.join(patterns)}; "
        f"{files} file(s) seen, formats: {shown}"
        + (f" -- {hint}" if hint else "")
    )
    return Skipped(str(base), "no-match", reason)


def triage(root: str | Path, patterns: tuple[str, ...] = DEFAULT_PATTERNS,
           max_files: int = 500) -> TriageResult:
    """Parse every ELF under *root*, and record what was skipped and why."""
    base = Path(root)
    candidates: list[Path] = []
    if base.is_file():
        candidates = [base]
    else:
        for pattern in patterns:
            candidates.extend(sorted(base.rglob(pattern)))

    result = TriageResult()
    for path in candidates[:max_files]:
        if not path.is_file():
            continue
        kind = sniff(path)
        if kind != "elf":
            result.skipped.append(Skipped(str(path), kind, skip_reason(kind)))
            continue
        info = parse(path)
        if info.valid:
            result.objects.append(info)
        else:
            result.skipped.append(
                Skipped(str(path), "elf", f"ELF header could not be parsed: {info.error}")
            )

    if not result.objects and not result.skipped and base.is_dir():
        # A directory is scanned by pattern, so a folder of .exe files would
        # otherwise produce "0 objects" with no explanation at all.
        note = _describe_directory(base, patterns)
        if note is not None:
            result.skipped.append(note)
    return result


def triage_dir(root: str | Path, patterns: tuple[str, ...] = DEFAULT_PATTERNS,
               max_files: int = 500) -> list[ElfInfo]:
    """Parsed ELF objects only; see :func:`triage` for the skipped files."""
    return triage(root, patterns=patterns, max_files=max_files).objects


def summarize(infos: list[ElfInfo]) -> dict:
    """Aggregate view: what classes of binaries are in this bundle."""
    by_abi: dict[str, int] = {}
    by_banner: dict[str, int] = {}
    by_type: dict[str, int] = {}
    no_exports: list[str] = []
    no_jni: list[str] = []
    not_stripped: list[str] = []

    for info in infos:
        by_abi[info.abi] = by_abi.get(info.abi, 0) + 1
        by_type[info.type_name] = by_type.get(info.type_name, 0) + 1
        key = info.banner or "<no .comment banner>"
        by_banner[key] = by_banner.get(key, 0) + 1
        name = Path(info.path).name
        if info.is_shared_library and not info.exports:
            no_exports.append(name)
        elif info.is_shared_library and not info.jni_entry_points:
            no_jni.append(name)
        if not info.stripped:
            not_stripped.append(name)

    return {
        "count": len(infos),
        "total_bytes": sum(info.size for info in infos),
        "by_abi": dict(sorted(by_abi.items(), key=lambda kv: -kv[1])),
        "by_type": by_type,
        "by_banner": dict(sorted(by_banner.items(), key=lambda kv: -kv[1])),
        "shared_objects_without_exports": sorted(no_exports),
        "shared_objects_without_jni_entry_points": sorted(no_jni),
        "not_stripped": sorted(not_stripped),
    }
