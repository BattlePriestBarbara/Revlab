"""Dependency-free PE triage.

Why hand-rolled instead of ``pefile``: the same reason as :mod:`revlab.elf` -- the
first question about a Windows binary ("what am I looking at, and is it worth the
decompilation budget") has to be answerable on a fresh machine with no wheels
installed and no virtual environment. A 1.2 MB launcher parses in milliseconds,
so the answer costs nothing before Ghidra's JVM even starts.

Covered: the COFF header (machine, timestamp, characteristics), the optional
header (magic, entry point, image base, subsystem, DLL characteristics), the
section table with per-section Shannon entropy, the import table (each DLL with
its function names, delay-loaded imports included) and whether a signature is
attached at all (``IMAGE_DIRECTORY_ENTRY_SECURITY``).

Not covered (deliberately, they are Ghidra's job): relocations, the Rich header,
the resource tree, .NET metadata, decompilation. Two limits are worth stating
loudly, because a report must not overstate what it knows:

* a certificate *table* proves a signature was attached, not that it verifies --
  checking the PKCS#7 blob is a job for ``signtool``/``osslsigncode``;
* and a high-entropy section is a hint about packing, not proof: compressed
  resources and legitimately encrypted blobs look exactly the same.

Everything in this module is a fact read off the file. "What it means" lives in
:mod:`revlab.heuristics`, which is where the thresholds a reader can argue with
belong.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"
#: The DOS header is 64 bytes and ``e_lfanew`` sits at offset 0x3C. A shorter
#: blob cannot be a PE whatever its first two bytes say, and reading past the end
#: of a truncated copy is how a triage pass turns into a traceback.
DOS_HEADER_SIZE = 0x40
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
#: Guard rails: the format allows 96 sections and 16 directories, but these caps
#: also stop a corrupt header from making us walk megabytes of garbage.
MAX_SECTIONS = 96
MAX_THUNKS = 4096
MAX_DESCRIPTORS = 512
#: A 64-byte section has a meaningless entropy; the floor keeps the number honest
#: (a short "high entropy" section is noise, not evidence of packing).
MIN_ENTROPY_BYTES = 512

MACHINES = {
    0x014C: "i386", 0x0162: "MIPS", 0x0166: "MIPS16", 0x0168: "MIPSFPU",
    0x0169: "MIPSFPU16", 0x01C0: "ARM", 0x01C2: "THUMB", 0x01C4: "ARMNT",
    0x01D3: "AM33", 0x01F0: "POWERPC", 0x0200: "IA64", 0x0266: "MIPS16",
    0x0366: "MIPSFPU", 0x0466: "MIPSFPU16", 0x0520: "TRICORE", 0x0CEF: "EBC",
    0x8664: "x86_64", 0x9041: "M32R", 0xAA64: "arm64", 0x5032: "riscv32",
    0x5064: "riscv64", 0x5128: "riscv128",
}
SUBSYSTEMS = {
    0: "unknown", 1: "native", 2: "windows-gui", 3: "windows-console",
    5: "os2-console", 7: "posix-console", 8: "native-windows", 9: "windows-ce",
    10: "efi-application", 11: "efi-boot-service", 12: "efi-runtime",
    13: "efi-rom", 14: "xbox", 16: "windows-boot-application",
}
COFF_CHARACTERISTICS = (
    (0x0001, "reloc-stripped"), (0x0002, "executable-image"),
    (0x0020, "large-address-aware"), (0x0100, "machine-32bit"),
    (0x2000, "dll"), (0x4000, "system"),
)
#: Names kept because they are the ones a report can say something about.
DLL_CHARACTERISTICS = (
    (0x0020, "high-entropy-va"), (0x0040, "dynamic-base"),
    (0x0080, "force-integrity"), (0x0100, "nx-compat"),
    (0x0200, "no-isolation"), (0x0400, "no-seh"), (0x0800, "no-bind"),
    (0x1000, "app-container"), (0x2000, "wdm-driver"), (0x4000, "guard-cf"),
    (0x8000, "terminal-server-aware"),
)
SECTION_CHARACTERISTICS = (
    (0x00000020, "code"), (0x00000040, "initialised-data"),
    (0x00000080, "uninitialised-data"), (0x02000000, "discardable"),
    (0x20000000, "execute"), (0x40000000, "read"), (0x80000000, "write"),
)
EXPORT_DIRECTORY, IMPORT_DIRECTORY, SECURITY_DIRECTORY = 0, 1, 4
DELAY_IMPORT_DIRECTORY, CLR_DIRECTORY = 13, 14
ORDINAL_FLAG_32 = 0x80000000
ORDINAL_FLAG_64 = 0x8000000000000000


@dataclass
class PeSection:
    """One section: the numbers a packer check reads first."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float

    @property
    def flags(self) -> list[str]:
        return [name for bit, name in SECTION_CHARACTERISTICS if self.characteristics & bit]

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["flags"] = self.flags
        return payload


@dataclass
class PeImport:
    """One imported DLL and the functions taken from it."""

    dll: str
    functions: list[str] = field(default_factory=list)
    delayed: bool = False

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["function_count"] = len(self.functions)
        return payload


@dataclass
class PeInfo:
    """Everything this pass knows about one PE file."""

    path: str
    valid: bool = False
    error: str | None = None
    magic: str = ""            # pe32 | pe32+
    machine: str = ""
    machine_id: int = 0
    bits: int = 0
    subsystem: str = ""
    timestamp: int = 0
    timestamp_iso: str = ""
    entry_point: int = 0
    image_base: int = 0
    characteristics: int = 0
    dll_characteristics: int = 0
    checksum: int = 0
    symbol_count: int = 0
    signature_offset: int = 0
    signature_size: int = 0
    is_dotnet: bool = False
    sections: list[PeSection] = field(default_factory=list)
    imports: list[PeImport] = field(default_factory=list)
    #: Structural oddities that a reader must see rather than infer, e.g. a
    #: truncated section table. Same convention as ``elf``'s limitation notes:
    #: the pass says what it could not read instead of silently reporting less.
    warnings: list[str] = field(default_factory=list)
    size: int = 0
    sha256: str = ""

    # ---- convenience -------------------------------------------------------
    @property
    def is_64bit(self) -> bool:
        return self.bits == 64

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    @property
    def is_signed(self) -> bool:
        """A certificate table is present; whether it *verifies* is another job."""
        return self.signature_size > 0

    @property
    def coff_flags(self) -> list[str]:
        return [name for bit, name in COFF_CHARACTERISTICS if self.characteristics & bit]

    @property
    def dll_flags(self) -> list[str]:
        return [name for bit, name in DLL_CHARACTERISTICS if self.dll_characteristics & bit]

    @property
    def section_names(self) -> list[str]:
        return [section.name for section in self.sections]

    @property
    def import_dlls(self) -> list[str]:
        return sorted({item.dll for item in self.imports if item.dll})

    @property
    def imported_functions(self) -> list[str]:
        """Flat, deduplicated function names -- what the API rules scan."""
        return sorted({name for item in self.imports for name in item.functions})

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["sections"] = [section.to_dict() for section in self.sections]
        payload["imports"] = [item.to_dict() for item in self.imports]
        payload["section_names"] = self.section_names
        payload["import_dlls"] = self.import_dlls
        payload["imported_functions"] = self.imported_functions
        payload["coff_flags"] = self.coff_flags
        payload["dll_flags"] = self.dll_flags
        payload["is_signed"] = self.is_signed
        payload["is_dll"] = self.is_dll
        return payload


def is_pe(path: str | Path, probe: int = 2) -> bool:
    """Cheap magic check, the PE counterpart of :func:`revlab.elf.is_elf`."""
    try:
        with Path(path).open("rb") as handle:
            return handle.read(probe) == DOS_MAGIC
    except OSError:
        return False


def _unpack(blob: bytes, fmt: str, offset: int) -> int:
    """Read a scalar, or 0 when the header claims bytes the file does not have."""
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(blob):
        return 0
    return int(struct.unpack_from(fmt, blob, offset)[0])


def _entropy(blob: bytes) -> float:
    """Shannon entropy in bits/byte: 0.0 = one repeated byte, 8.0 = random.

    Counted with :class:`collections.Counter` so the whole pass stays on the
    standard library. Section sizes are small enough that this is free, and the
    number is only ever used against one threshold.
    """
    if not blob:
        return 0.0
    counts = Counter(blob)
    total = len(blob)
    return round(-sum((n / total) * math.log2(n / total) for n in counts.values()), 4)


def _cstring(blob: bytes, offset: int, limit: int = 256) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset, offset + limit)
    if end == -1:
        end = min(len(blob), offset + limit)
    return blob[offset:end].decode("utf-8", "replace")


def _rva_to_offset(sections: list[PeSection], rva: int) -> int | None:
    """Map a virtual address to a file offset using the section table.

    Headers are addressable too (the import directory can legitimately live in
    them), and a header RVA simply is its file offset because the loader maps
    them one-to-one from the start of the file.
    """
    if rva <= 0:
        return None
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            return section.raw_offset + (rva - section.virtual_address)
    return None


def _thunk_names(blob: bytes, sections: list[PeSection], table_rva: int, bits: int,
                 limit: int = MAX_THUNKS) -> list[str]:
    """Function names from an import thunk table (ILT/IAT/delay INT)."""
    base = _rva_to_offset(sections, table_rva)
    if base is None:
        return []
    step = 8 if bits == 64 else 4
    fmt = "<Q" if bits == 64 else "<I"
    flag = ORDINAL_FLAG_64 if bits == 64 else ORDINAL_FLAG_32
    names: list[str] = []
    for index in range(limit):
        entry = _unpack(blob, fmt, base + index * step)
        if entry == 0:
            break
        if entry & flag:
            names.append(f"Ordinal {entry & 0xFFFF}")
            continue
        target = _rva_to_offset(sections, entry)
        if target is None:
            names.append(f"<unresolved rva 0x{entry:x}>")
            continue
        # A hint/name entry is a 2-byte hint followed by the name.
        name = _cstring(blob, target + 2)
        names.append(name or f"<unreadable rva 0x{entry:x}>")
    return names


def _parse_imports(blob: bytes, sections: list[PeSection], directory: tuple[int, int],
                   bits: int, image_base: int, delayed: bool) -> list[PeImport]:
    """Walk one import directory, ordinary (index 1) or delay-loaded (index 13).

    The directory's own ``Size`` field is not trusted as an iteration bound: real
    binaries ship with it set to zero, so the walk is driven by the all-zero
    terminator descriptor, with a hard cap and a break on the first descriptor
    whose DLL name cannot be resolved (garbage, not a real entry).
    """
    rva, _size = directory
    start = _rva_to_offset(sections, rva)
    if start is None:
        return []
    descriptor_size = 32 if delayed else 20
    out: list[PeImport] = []
    for index in range(MAX_DESCRIPTORS):
        base = start + index * descriptor_size
        if base + descriptor_size > len(blob):
            break
        if delayed:
            attributes = _unpack(blob, "<I", base)
            # IMAGE_DELAYLOAD_DESCRIPTOR.dlattrRva: without it the fields hold
            # virtual addresses, so subtract the image base to get an RVA.
            adjust = 0 if attributes & 1 else image_base
            name_rva = _unpack(blob, "<I", base + 4) - adjust
            thunk_rva = _unpack(blob, "<I", base + 16) - adjust
            if not thunk_rva:
                thunk_rva = _unpack(blob, "<I", base + 12) - adjust
        else:
            # OriginalFirstThunk first: it is the one that keeps hint/name RVAs.
            thunk_rva = _unpack(blob, "<I", base)
            name_rva = _unpack(blob, "<I", base + 12)
            if not thunk_rva:
                thunk_rva = _unpack(blob, "<I", base + 16)
        if not (name_rva or thunk_rva):
            break                       # the all-zero terminator
        name_offset = _rva_to_offset(sections, name_rva)
        dll = _cstring(blob, name_offset) if name_offset is not None else ""
        if not dll:
            break                       # unresolvable name: stop, do not invent
        out.append(
            PeImport(
                dll=dll,
                functions=_thunk_names(blob, sections, thunk_rva, bits),
                delayed=delayed,
            )
        )
    return out


def parse(path: str | Path) -> PeInfo:
    """Parse one PE file. Never raises: a bad file comes back with ``error`` set."""
    info = PeInfo(path=str(path))
    try:
        blob = Path(path).read_bytes()
    except OSError as exc:
        info.error = f"cannot read file: {exc}"
        return info

    info.size = len(blob)
    info.sha256 = hashlib.sha256(blob).hexdigest()

    if len(blob) < DOS_HEADER_SIZE:
        info.error = (
            f"file is too short for a DOS header ({len(blob)} B < {DOS_HEADER_SIZE} B): "
            "truncated copy, or not an executable at all"
        )
        return info
    if blob[:2] != DOS_MAGIC:
        info.error = "not a PE: the DOS magic (MZ) is missing"
        return info
    pe_offset = _unpack(blob, "<I", 0x3C)
    if blob[pe_offset:pe_offset + 4] != PE_SIGNATURE:
        info.error = (
            f"no PE signature at 0x{pe_offset:x} (where the DOS stub points): "
            "a DOS or 16-bit executable, or a truncated copy"
        )
        return info

    coff = pe_offset + 4
    info.machine_id = _unpack(blob, "<H", coff)
    info.machine = MACHINES.get(info.machine_id, f"unknown(0x{info.machine_id:04x})")
    section_count = _unpack(blob, "<H", coff + 2)
    info.timestamp = _unpack(blob, "<I", coff + 4)
    info.symbol_count = _unpack(blob, "<I", coff + 12)
    optional_size = _unpack(blob, "<H", coff + 16)
    info.characteristics = _unpack(blob, "<H", coff + 18)
    info.timestamp_iso = _timestamp_iso(info.timestamp)

    optional = coff + COFF_HEADER_SIZE
    if optional_size == 0 or optional + optional_size > len(blob):
        info.error = "no optional header: this is a COFF object, not a PE image"
        return info

    magic = _unpack(blob, "<H", optional)
    if magic == 0x20B:
        info.magic, info.bits = "pe32+", 64
    elif magic == 0x10B:
        info.magic, info.bits = "pe32", 32
    elif magic == 0x107:
        info.magic, info.bits = "rom-image", 32
    else:
        info.error = f"unknown optional header magic 0x{magic:04x}"
        return info

    info.entry_point = _unpack(blob, "<I", optional + 16)
    info.image_base = (
        _unpack(blob, "<Q", optional + 24) if info.is_64bit
        else _unpack(blob, "<I", optional + 28)
    )
    info.checksum = _unpack(blob, "<I", optional + 64)
    subsystem = _unpack(blob, "<H", optional + 68)
    info.subsystem = SUBSYSTEMS.get(subsystem, f"unknown(0x{subsystem:04x})")
    info.dll_characteristics = _unpack(blob, "<H", optional + 70)

    # PE32 and PE32+ differ in more than the magic: the data directories start at
    # 96 there and at 112 here, because the base/stack/heap fields widened.
    directory_count_offset = 108 if info.is_64bit else 92
    directories_offset = 112 if info.is_64bit else 96
    count = min(_unpack(blob, "<I", optional + directory_count_offset), 16)
    directories = [
        (_unpack(blob, "<I", optional + directories_offset + index * 8),
         _unpack(blob, "<I", optional + directories_offset + index * 8 + 4))
        for index in range(count)
    ]

    info.sections = _parse_sections(blob, optional + optional_size, section_count, info)
    info.imports = _imports(blob, info, directories)

    if len(directories) > SECURITY_DIRECTORY:
        info.signature_offset, info.signature_size = directories[SECURITY_DIRECTORY]
        if info.signature_size and info.signature_offset + info.signature_size > info.size:
            info.warnings.append(
                f"certificate table (offset 0x{info.signature_offset:x}, "
                f"{info.signature_size} B) runs past the end of the file"
            )

    clr = directories[CLR_DIRECTORY] if len(directories) > CLR_DIRECTORY else (0, 0)
    info.is_dotnet = bool(clr[1]) or any(
        item.dll.lower() == "mscoree.dll" for item in info.imports
    )

    info.valid = True
    return info


def _timestamp_iso(stamp: int) -> str:
    """The COFF timestamp as UTC, or empty when it is not a plausible date."""
    if not 315532800 <= stamp <= 4102444800:      # 1980-01-01 .. 2100-01-01
        return ""
    moment = datetime.fromtimestamp(stamp, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_sections(blob: bytes, table: int, declared: int, info: PeInfo) -> list[PeSection]:
    """Read the section table and compute one entropy per raw section body."""
    sections: list[PeSection] = []
    for index in range(min(declared, MAX_SECTIONS)):
        base = table + index * SECTION_HEADER_SIZE
        if base + SECTION_HEADER_SIZE > len(blob):
            info.warnings.append(
                f"section table truncated: {declared} declared, {index} readable"
            )
            break
        name = blob[base:base + 8].split(b"\x00")[0].decode("ascii", "replace")
        raw_size = _unpack(blob, "<I", base + 16)
        raw_offset = _unpack(blob, "<I", base + 20)
        data = blob[raw_offset:raw_offset + raw_size] if raw_size else b""
        if raw_size and len(data) < raw_size:
            info.warnings.append(
                f"{name or f'section {index}'} claims {raw_size} B at "
                f"0x{raw_offset:x} but only {len(data)} B are present"
            )
        sections.append(
            PeSection(
                name=name or f"<section {index}>",
                virtual_address=_unpack(blob, "<I", base + 12),
                virtual_size=_unpack(blob, "<I", base + 8),
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=_unpack(blob, "<I", base + 36),
                # Entropy over what the file actually holds, so a truncated
                # section cannot report a number computed from missing bytes.
                entropy=_entropy(data),
            )
        )
    if declared > MAX_SECTIONS:
        info.warnings.append(f"{declared} sections declared; only {MAX_SECTIONS} read")
    return sections


def _imports(blob: bytes, info: PeInfo, directories: list[tuple[int, int]]) -> list[PeImport]:
    """Ordinary imports plus delay-loaded ones, which are just as real."""
    out: list[PeImport] = []
    for index, delayed in ((IMPORT_DIRECTORY, False), (DELAY_IMPORT_DIRECTORY, True)):
        if len(directories) <= index:
            continue
        out.extend(
            _parse_imports(blob, info.sections, directories[index], info.bits,
                           info.image_base, delayed)
        )
    if not out:
        info.warnings.append(
            "no import table: a resource-only image, or the APIs are resolved "
            "dynamically (LoadLibrary/GetProcAddress) throughout"
        )
    return out


def summarize(info: PeInfo) -> dict:
    """The record-sized view of a parse: every number, none of the bulk.

    The full parse (every imported function, every section) goes to the JSON
    artifact; this is what a record line and the report can quote cheaply.
    """
    return {
        "valid": info.valid,
        "error": info.error,
        "path": info.path,
        "magic": info.magic,
        "machine": info.machine,
        "bits": info.bits,
        "subsystem": info.subsystem,
        "kind": "dll" if info.is_dll else "executable",
        "entry_point": f"0x{info.entry_point:x}",
        "image_base": f"0x{info.image_base:x}",
        "compiled": info.timestamp_iso,
        "dll_flags": info.dll_flags,
        "dotnet": info.is_dotnet,
        "section_count": len(info.sections),
        "sections": [
            {"name": section.name, "entropy": section.entropy,
             "raw_size": section.raw_size, "flags": section.flags}
            for section in info.sections
        ],
        "import_dlls": info.import_dlls,
        "import_function_count": len(info.imported_functions),
        "signed": info.is_signed,
        "signature_size": info.signature_size,
        "warnings": info.warnings,
        "sha256": info.sha256,
        "size": info.size,
    }
